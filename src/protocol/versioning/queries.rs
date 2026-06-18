//! Queries and guards for projected protocol versioning state.

use crate::core::db::{quoted_identifier_list, quoted_table_name, Db, TableName};
use crate::core::effects::StorageRequirement;
use crate::core::facts::FactId;
use rusqlite::types::ValueRef;
use rusqlite::{OptionalExtension, Row};

use super::CURRENT_PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRow {
    pub update_fact_id: FactId,
    pub protocol_version: u32,
    pub applied_at_ms: u64,
}

pub fn current_version(store: &Db) -> Result<Option<VersionRow>, String> {
    store
        .conn()
        .query_row(
            "SELECT update_fact_id, protocol_version, applied_at_ms
             FROM protocol_version_rows
             ORDER BY applied_at_ms DESC, update_fact_id DESC
             LIMIT 1",
            [],
            decode_version_row,
        )
        .optional()
        .map_err(|err| format!("read projected protocol version: {err}"))
}

pub fn storage_ready(store: &Db) -> Result<bool, String> {
    match current_version(store)? {
        Some(row) => Ok(row.protocol_version == CURRENT_PROTOCOL_VERSION),
        None => retained_fact_count(store).map(|facts| facts == 0),
    }
}

pub fn require_storage_requirement(
    store: &Db,
    requirement: StorageRequirement,
) -> Result<(), String> {
    match requirement {
        StorageRequirement::Current(version) => require_storage_version(store, version),
        StorageRequirement::MaintenanceBypass => Ok(()),
    }
}

pub fn require_storage_version(store: &Db, expected: u32) -> Result<(), String> {
    match current_version(store)? {
        Some(row) if row.protocol_version == expected => Ok(()),
        Some(row) => Err(format!(
            "storage version mismatch: required_version={expected} stored_version={}",
            row.protocol_version
        )),
        None => Err(format!(
            "storage version mismatch: required_version={expected} stored_version=missing"
        )),
    }
}

fn decode_version_row(row: &Row<'_>) -> rusqlite::Result<VersionRow> {
    let id = row.get::<_, Vec<u8>>(0)?;
    let update_fact_id = id.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName("protocol version fact id is not 32 bytes".into())
    })?;
    let protocol_version = u32::try_from(row.get::<_, i64>(1)?).map_err(|_| {
        rusqlite::Error::InvalidParameterName("protocol version exceeds u32".into())
    })?;
    let applied_at_ms = u64::try_from(row.get::<_, i64>(2)?).map_err(|_| {
        rusqlite::Error::InvalidParameterName("protocol version applied_at_ms is negative".into())
    })?;
    Ok(VersionRow {
        update_fact_id,
        protocol_version,
        applied_at_ms,
    })
}

fn retained_fact_count(store: &Db) -> Result<usize, String> {
    store
        .table_row_count(crate::core::schema::FACTS)
        .map_err(|err| format!("count retained facts for protocol version guard: {err}"))
}

/// One hashed state area in a [`StateSummary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AreaSummary {
    /// Table name owning this area.
    pub area: String,
    /// Canonical hash of the area's rows.
    pub hash: [u8; 32],
    /// Row count in the area.
    pub count: usize,
}

/// A stable, order-independent digest of rebuild-relevant state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSummary {
    /// Overall digest combining every per-area hash and count.
    pub state_hash: [u8; 32],
    /// Per-area hashes and counts, ordered by area name.
    pub areas: Vec<AreaSummary>,
}

/// Canonical digest of one schema-declared summary table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSummary {
    /// Table name owning this area.
    pub table: String,
    /// Canonical hash of the table's rows.
    pub hash: [u8; 32],
    /// Row count in the table.
    pub count: usize,
}

/// Compute the canonical, order-independent digest of rebuild-relevant state.
pub fn state_summary(db: &Db) -> Result<StateSummary, String> {
    let mut areas = Vec::new();
    for summary in state_summary_table_hashes(db)? {
        areas.push(AreaSummary {
            area: summary.table,
            hash: summary.hash,
            count: summary.count,
        });
    }
    areas.sort_by(|left, right| left.area.cmp(&right.area));

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:state-summary:v1");
    for area in &areas {
        hasher.update(&(area.area.len() as u64).to_le_bytes());
        hasher.update(area.area.as_bytes());
        hasher.update(&(area.count as u64).to_le_bytes());
        hasher.update(&area.hash);
    }
    Ok(StateSummary {
        state_hash: *hasher.finalize().as_bytes(),
        areas,
    })
}

/// Hash every schema-declared summary table.
pub fn state_summary_table_hashes(db: &Db) -> Result<Vec<TableSummary>, String> {
    let mut summaries = Vec::with_capacity(db.replay_summary_tables().len());
    for table in db.replay_summary_tables() {
        summaries.push(hash_table(db, *table)?);
    }
    Ok(summaries)
}

/// Hash one table's rows canonically, independent of insertion order.
///
/// Rows are ordered by every column so the digest depends only on content, and
/// each cell is serialized with a type tag so distinct SQLite types never
/// alias.
fn hash_table(db: &Db, table: TableName) -> Result<TableSummary, String> {
    let quoted = quoted_table_name(table).map_err(|err| err.to_string())?;
    let columns = table_columns(db, &quoted)?;
    if columns.is_empty() {
        return Err(format!("table {} has no columns to hash", table.as_str()));
    }
    let column_list = quoted_identifier_list(&columns).map_err(|err| err.to_string())?;

    let mut stmt = db
        .conn()
        .prepare(&format!(
            "SELECT {column_list} FROM {quoted} ORDER BY {column_list}"
        ))
        .map_err(|err| format!("prepare hash scan for {}: {err}", table.as_str()))?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:store-table-summary:v1");
    hasher.update(&(table.as_str().len() as u64).to_le_bytes());
    hasher.update(table.as_str().as_bytes());
    for column in &columns {
        hasher.update(&(column.len() as u64).to_le_bytes());
        hasher.update(column.as_bytes());
    }

    let column_count = columns.len();
    let mut count = 0usize;
    let mut rows = stmt
        .query([])
        .map_err(|err| format!("scan {}: {err}", table.as_str()))?;
    while let Some(row) = rows
        .next()
        .map_err(|err| format!("scan {}: {err}", table.as_str()))?
    {
        for index in 0..column_count {
            let value = row
                .get_ref(index)
                .map_err(|err| format!("read {} cell: {err}", table.as_str()))?;
            hash_cell(&mut hasher, value);
        }
        count += 1;
    }
    Ok(TableSummary {
        table: table.as_str().to_string(),
        hash: *hasher.finalize().as_bytes(),
        count,
    })
}

fn table_columns(db: &Db, quoted_table: &str) -> Result<Vec<String>, String> {
    let mut stmt = db
        .conn()
        .prepare(&format!("PRAGMA table_info({quoted_table})"))
        .map_err(|err| format!("read columns: {err}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|err| format!("read columns: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("read columns: {err}"))
}

fn hash_cell(hasher: &mut blake3::Hasher, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update(&[0u8]),
        ValueRef::Integer(int) => {
            hasher.update(&[1u8]);
            hasher.update(&int.to_le_bytes())
        }
        ValueRef::Real(real) => {
            hasher.update(&[2u8]);
            hasher.update(&real.to_bits().to_le_bytes())
        }
        ValueRef::Text(text) => {
            hasher.update(&[3u8]);
            hasher.update(&(text.len() as u64).to_le_bytes());
            hasher.update(text)
        }
        ValueRef::Blob(blob) => {
            hasher.update(&[4u8]);
            hasher.update(&(blob.len() as u64).to_le_bytes());
            hasher.update(blob)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::runtime::Runtime;
    use crate::protocol::app::MATCH_RUNTIME;
    use crate::protocol::versioning::update::{author::update_fact, fact::UpdateFact};
    use rusqlite::params;

    fn replace_stored_version_for_test(store: &Db, protocol_version: u32) {
        store
            .write_transaction(|tx| {
                tx.conn().execute("DELETE FROM protocol_version_rows", [])?;
                tx.conn().execute(
                    "INSERT INTO protocol_version_rows
                        (update_fact_id, protocol_version, applied_at_ms)
                     VALUES (?1, ?2, ?3)",
                    params![vec![1_u8; 32], i64::from(protocol_version), 1_i64],
                )?;
                Ok(())
            })
            .expect("replace stored protocol version");
    }

    #[test]
    fn storage_guard_tracks_the_projected_release_marker() {
        let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");
        assert!(
            storage_ready(runtime.db()).expect("empty db guard"),
            "fresh databases seed the current version marker"
        );

        replace_stored_version_for_test(runtime.db(), CURRENT_PROTOCOL_VERSION - 1);
        let update = update_fact(UpdateFact {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            applied_at_ms: 44,
        })
        .expect("update fact");
        runtime.submit_fact(update);
        assert!(
            !storage_ready(runtime.db()).expect("stale version marker"),
            "stale storage requires update"
        );

        runtime
            .drain_durable_projection(1)
            .expect("project live update");
        assert_eq!(
            current_version(runtime.db())
                .expect("current version")
                .expect("version row")
                .protocol_version,
            CURRENT_PROTOCOL_VERSION
        );
        assert!(
            storage_ready(runtime.db()).expect("current marker"),
            "storage readiness is the release marker check; projector/query guards own table access"
        );
    }
}

//! Queries and guards for the projected protocol release marker.

use crate::core::db::Db;
use crate::core::effects::StorageRequirement;
use crate::core::facts::FactId;
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

pub fn ensure_storage_ready(store: &Db) -> Result<(), String> {
    if storage_ready(store)? {
        return Ok(());
    }
    let stored = current_version(store)?
        .map(|row| row.protocol_version.to_string())
        .unwrap_or_else(|| "missing".to_string());
    Err(format!(
        "protocol update required: stored_version={stored} current_version={CURRENT_PROTOCOL_VERSION}; start the daemon or run `update` and let projection drain"
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::runtime::Runtime;
    use crate::protocol::app::MATCH_RUNTIME;
    use crate::protocol::versioning::update::{update_fact, UpdateFact};
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

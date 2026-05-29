//! Stable summaries of replay-relevant runtime state.
//!
//! Replay tests compare state after wiping and rebuilding derived tables. This
//! module owns the generic digest surface: core tables, protocol row tables,
//! typed read-model tables, and replay queues are serialized in deterministic
//! table/row/column order. Volatile socket queues and local scheduler state are
//! deliberately excluded.

use crate::core::runtime::RuntimeDescription;
use crate::core::schema::{
    CONTEXT_EDGES, EPHEMERAL_PROJECTION_INPUTS, INTENTS, LOCAL_FACT_ADMISSIONS, LOCAL_INTENTS,
    PENDING_PROJECTION, PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::store::{quoted_identifier, quoted_table_name_str, Store};
use rusqlite::types::ValueRef;
use rusqlite::OptionalExtension;
use std::collections::BTreeSet;

/// Digest and count for one replay-owned table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AreaSummary {
    pub name: String,
    pub count: usize,
    pub hash: String,
}

/// Stable summary of replay-relevant state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSummary {
    pub state_hash: String,
    pub areas: Vec<AreaSummary>,
}

/// Summarize the replay-relevant rows owned by core and the protocol runtime.
pub fn summarize(description: &RuntimeDescription, store: &Store) -> Result<StateSummary, String> {
    let tables = summary_tables(description);
    let mut areas = Vec::with_capacity(tables.len());
    let mut overall = blake3::Hasher::new();
    overall.update(b"topo:state-summary:v1");
    for table in tables {
        let area = summarize_table(store, table)?;
        overall.update(area.name.as_bytes());
        overall.update(&(area.count as u64).to_be_bytes());
        overall.update(area.hash.as_bytes());
        areas.push(area);
    }
    Ok(StateSummary {
        state_hash: hex(overall.finalize().as_bytes()),
        areas,
    })
}

fn summary_tables(description: &RuntimeDescription) -> Vec<&'static str> {
    let mut tables = BTreeSet::<&'static str>::new();
    for table in [
        "facts",
        LOCAL_FACT_ADMISSIONS.as_str(),
        CONTEXT_EDGES.as_str(),
        TIME_WAKES.as_str(),
        PENDING_PROJECTION.as_str(),
        PENDING_TIME_RANGES.as_str(),
        INTENTS.as_str(),
        LOCAL_INTENTS.as_str(),
        EPHEMERAL_PROJECTION_INPUTS.as_str(),
    ] {
        tables.insert(table);
    }
    for table in description.row_mutation_tables {
        tables.insert(table.as_str());
    }
    for source in description.schema_sources {
        for table in source.row_tables {
            if matches!(table.as_str(), "network_in" | "network_out") {
                continue;
            }
            tables.insert(table.as_str());
        }
    }
    tables.into_iter().collect()
}

fn summarize_table(store: &Store, table: &str) -> Result<AreaSummary, String> {
    let columns = table_columns(store, table)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:state-summary-table:v1");
    hasher.update(table.as_bytes());
    for column in &columns {
        hasher.update(column.as_bytes());
    }

    let quoted_table = quoted_table_name_str(table).map_err(|err| err.to_string())?;
    let selected_columns = columns
        .iter()
        .map(|column| quoted_identifier(column).map_err(|err| err.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let order = selected_columns.join(", ");
    let sql = format!(
        "SELECT {} FROM {quoted_table} ORDER BY {order}",
        selected_columns.join(", ")
    );
    let mut stmt = store
        .conn()
        .prepare(&sql)
        .map_err(|err| format!("prepare summary query for {table}: {err}"))?;
    let mut rows = stmt
        .query([])
        .map_err(|err| format!("query summary rows for {table}: {err}"))?;
    let mut count = 0usize;
    while let Some(row) = rows
        .next()
        .map_err(|err| format!("read summary rows for {table}: {err}"))?
    {
        count += 1;
        hasher.update(&(columns.len() as u64).to_be_bytes());
        for index in 0..columns.len() {
            encode_value(
                row.get_ref(index).map_err(|err| err.to_string())?,
                &mut hasher,
            );
        }
    }

    Ok(AreaSummary {
        name: table.to_string(),
        count,
        hash: hex(hasher.finalize().as_bytes()),
    })
}

fn table_columns(store: &Store, table: &str) -> Result<Vec<String>, String> {
    let quoted = quoted_table_name_str(table).map_err(|err| err.to_string())?;
    let mut stmt = store
        .conn()
        .prepare(&format!("PRAGMA table_info({quoted})"))
        .map_err(|err| format!("read schema for {table}: {err}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|err| format!("read schema for {table}: {err}"))?;
    let columns = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("read schema for {table}: {err}"))?;
    if columns.is_empty() && !table_exists(store, table)? {
        return Err(format!("summary table {table} does not exist"));
    }
    Ok(columns)
}

fn table_exists(store: &Store, table: &str) -> Result<bool, String> {
    store
        .conn()
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1
             UNION ALL
             SELECT name FROM sqlite_temp_master WHERE type = 'table' AND name = ?1
             LIMIT 1",
            [table],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|err| format!("check table existence for {table}: {err}"))
}

fn encode_value(value: ValueRef<'_>, hasher: &mut blake3::Hasher) {
    match value {
        ValueRef::Null => {
            hasher.update(b"n");
        }
        ValueRef::Integer(value) => {
            hasher.update(b"i");
            hasher.update(&value.to_be_bytes());
        }
        ValueRef::Real(value) => {
            hasher.update(b"r");
            hasher.update(&value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => {
            hasher.update(b"t");
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        ValueRef::Blob(value) => {
            hasher.update(b"b");
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
    };
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

use crate::store::{EventRecord, Store};

use super::codec;
use super::tables;

pub fn staged_records(store: &Store) -> Result<Vec<EventRecord>, String> {
    let rows = store
        .table_rows(tables::STAGED_DEPENDENT_EVENTS)
        .map_err(|err| format!("load staged dependent events: {err}"))?;
    let mut records = Vec::with_capacity(rows.len());
    for (_, bytes) in rows {
        records.push(codec::record_from_bytes(bytes)?);
    }
    Ok(records)
}

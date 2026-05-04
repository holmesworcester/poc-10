use crate::core::store::Store;
use crate::protocol::event_modules::types::EventRecord;

use super::codec;
use super::tables;

pub fn staged_records(store: &Store) -> Result<Vec<EventRecord>, String> {
    let rows = store
        .table_rows(tables::STAGED_EVENTS_WITH_DEPS)
        .map_err(|err| format!("load staged event_with_deps: {err}"))?;
    let mut records = Vec::with_capacity(rows.len());
    for (_, bytes) in rows {
        records.push(codec::record_from_bytes(bytes)?);
    }
    Ok(records)
}

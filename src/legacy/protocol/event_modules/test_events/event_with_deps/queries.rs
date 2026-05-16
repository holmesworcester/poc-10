//! Read-only view of staged dependency-cascade events.
//!
//! Replay tests load staged bytes through this query and submit them back
//! through the CLI/common worker. The query does not mark progress; replay order
//! is a caller decision.

use crate::core::store::Store;
use crate::legacy::protocol::event_modules::types::EventRecord;

use super::layout;
use super::rows;

pub fn staged_records(store: &Store) -> Result<Vec<EventRecord>, String> {
    let rows = store
        .table_rows(rows::STAGED_EVENTS_WITH_DEPS)
        .map_err(|err| format!("load staged event_with_deps: {err}"))?;
    let mut records = Vec::with_capacity(rows.len());
    for (_, bytes) in rows {
        records.push(layout::record_from_bytes(bytes)?);
    }
    Ok(records)
}

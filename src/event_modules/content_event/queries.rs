//! Read-only content-event projections.

use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::event_modules::content_event::rows;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContentCount {
    pub content_events: usize,
    pub content_payload_bytes: u64,
    pub max_timestamp: u64,
}

pub fn count_for_workspace(store: &Store, workspace_id: FactId) -> Result<ContentCount, String> {
    let mut count = ContentCount::default();
    for (key, value) in store
        .table_rows_with_key_prefix(rows::CONTENT_EVENT_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("read content event rows: {err}"))?
    {
        let row = rows::decode_content_event_row(&key, &value)?;
        count.content_events += 1;
        count.content_payload_bytes = count
            .content_payload_bytes
            .checked_add(row.payload_bytes)
            .ok_or_else(|| "content payload byte count overflows u64".to_string())?;
        count.max_timestamp = count.max_timestamp.max(row.timestamp);
    }
    Ok(count)
}

pub fn max_timestamp(store: &Store) -> Result<u64, String> {
    let mut max_timestamp = 0;
    for (key, value) in store
        .table_rows(rows::CONTENT_EVENT_ROWS)
        .map_err(|err| format!("read content event rows: {err}"))?
    {
        let row = rows::decode_content_event_row(&key, &value)?;
        max_timestamp = max_timestamp.max(row.timestamp);
    }
    Ok(max_timestamp)
}

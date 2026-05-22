//! Read-only queries over projected content events.
//!
//! Content events are append-style payload records. Projection owns their
//! validation and row writes; this file owns aggregate views used by commands
//! and status reporting. Keep write behavior out of this module so callers can
//! rely on these helpers being side-effect free snapshots of `content_event_rows`.

use crate::core::facts::FactId;
use crate::core::store::Store;
use rusqlite::params;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContentCount {
    pub content_events: usize,
    pub content_payload_bytes: u64,
    pub max_timestamp: u64,
}

pub fn count_for_workspace(store: &Store, workspace_id: FactId) -> Result<ContentCount, String> {
    store
        .conn()
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0), COALESCE(MAX(timestamp), 0)
             FROM content_event_rows
             WHERE workspace_id = ?1",
            params![workspace_id],
            |row| {
                Ok(ContentCount {
                    content_events: row.get::<_, i64>(0)? as usize,
                    content_payload_bytes: row.get::<_, i64>(1)? as u64,
                    max_timestamp: row.get::<_, i64>(2)? as u64,
                })
            },
        )
        .map_err(|err| format!("read content event rows: {err}"))
}

pub fn max_timestamp(store: &Store) -> Result<u64, String> {
    store
        .conn()
        .query_row(
            "SELECT COALESCE(MAX(timestamp), 0) FROM content_event_rows",
            [],
            |row| row.get::<_, i64>(0).map(|value| value as u64),
        )
        .map_err(|err| format!("read content event rows: {err}"))
}

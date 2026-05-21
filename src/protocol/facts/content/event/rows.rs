//! Content-event projection rows.
//!
//! Rows are keyed by `workspace_id || content_fact_id` so callers can scan a
//! single workspace's content without decoding the fact store. The value
//! stores the timestamp and the original payload byte count.

use crate::core::intents::TableInsert;
use crate::core::select::Value;
use crate::core::store::TableName;

use super::fact::{ContentEventFact, WorkspaceId};

pub const CONTENT_EVENT_ROWS: TableName = TableName::new("content_event_rows");
const CONTENT_EVENT_COLUMNS: &[&str] = &["workspace_id", "fact_id", "timestamp", "payload_bytes"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentEventRow {
    pub workspace_id: WorkspaceId,
    pub fact_id: [u8; 32],
    pub timestamp: u64,
    pub payload_bytes: u64,
}

pub fn content_event_row(fact_id: [u8; 32], fact: &ContentEventFact) -> TableInsert {
    let payload_bytes: u64 = fact.payload.len() as u64;
    TableInsert {
        table: CONTENT_EVENT_ROWS,
        columns: CONTENT_EVENT_COLUMNS,
        values: vec![
            Value::Bytes(fact.workspace_id.to_vec()),
            Value::Bytes(fact_id.to_vec()),
            Value::U64(fact.timestamp),
            Value::U64(payload_bytes),
        ],
    }
}

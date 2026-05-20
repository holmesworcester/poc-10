//! Content-event projection rows.
//!
//! Rows are keyed by `workspace_id || content_fact_id` so callers can scan a
//! single workspace's content without decoding the fact store. The value
//! stores the timestamp and the original payload byte count.

use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use super::fact::{ContentEventFact, WorkspaceId};

pub const CONTENT_EVENT_ROWS: TableName = TableName::new("content_event_rows");
pub const ROW_VALUE_BYTES: usize = 8 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentEventRow {
    pub workspace_id: WorkspaceId,
    pub fact_id: [u8; 32],
    pub timestamp: u64,
    pub payload_bytes: u64,
}

pub fn content_event_key(workspace_id: &WorkspaceId, fact_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(fact_id);
    key
}

pub fn content_event_row(fact_id: [u8; 32], fact: &ContentEventFact) -> Result<TableRow, String> {
    let payload_bytes: u64 = fact.payload.len() as u64;
    let mut writer = wire::Writer::with_capacity(ROW_VALUE_BYTES);
    writer.u64be(fact.timestamp);
    writer.u64be(payload_bytes);
    Ok(TableRow {
        table: CONTENT_EVENT_ROWS,
        key: content_event_key(&fact.workspace_id, &fact_id),
        value: writer.finish(),
    })
}

pub fn decode_content_event_row(key: &[u8], value: &[u8]) -> Result<ContentEventRow, String> {
    if key.len() != 64 {
        return Err("content event row key is malformed".to_string());
    }
    let mut key_reader = wire::Reader::new(key);
    let workspace_id = key_reader.array().map_err(wire_err)?;
    let fact_id = key_reader.array().map_err(wire_err)?;
    key_reader.finish().map_err(wire_err)?;
    let mut value_reader = wire::Reader::new(value);
    let timestamp = value_reader.u64be().map_err(wire_err)?;
    let payload_bytes = value_reader.u64be().map_err(wire_err)?;
    value_reader.finish().map_err(wire_err)?;
    Ok(ContentEventRow {
        workspace_id,
        fact_id,
        timestamp,
        payload_bytes,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

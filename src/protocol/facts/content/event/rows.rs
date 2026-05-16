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
    let mut value = vec![0; ROW_VALUE_BYTES];
    wire::put_u64be(fact.timestamp, &mut value[0..8]).map_err(wire_err)?;
    wire::put_u64be(payload_bytes, &mut value[8..16]).map_err(wire_err)?;
    Ok(TableRow {
        table: CONTENT_EVENT_ROWS,
        key: content_event_key(&fact.workspace_id, &fact_id),
        value,
    })
}

pub fn decode_content_event_row(key: &[u8], value: &[u8]) -> Result<ContentEventRow, String> {
    if key.len() != 64 {
        return Err("content event row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut fact_id = [0; 32];
    fact_id.copy_from_slice(&key[32..64]);
    if value.len() != ROW_VALUE_BYTES {
        return Err("content event row value is malformed".to_string());
    }
    let timestamp = wire::take_u64be(&value[0..8]).map_err(wire_err)?;
    let payload_bytes = wire::take_u64be(&value[8..16]).map_err(wire_err)?;
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

//! Sync-owned work tables.
//!
//! Sync frames are connection-scoped protocol events. Outbound frames project
//! into the connection outbox because they are already answers ready for
//! wrapping. Inbound frames project here instead: the projector records that
//! the sync worker has stateful comparison work to do, and the worker later
//! drains these rows by connection.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::types::EventId;

pub const INBOUND_FRAMES: TableName = TableName::new("sync.inbound_frames");

pub const SCHEMAS: &[Schema] = &[Schema::temp_row_table(
    "sync.inbound_frames.v1",
    INBOUND_FRAMES,
)];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundFrameWork {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
    pub frame_bytes: Vec<u8>,
}

impl InboundFrameWork {
    pub fn key(&self) -> Vec<u8> {
        inbound_frame_key(self.connection_id, self.event_id)
    }
}

pub fn inbound_frame_row(
    connection_id: ConnectionId,
    event_id: EventId,
    frame_bytes: Vec<u8>,
) -> TableRow {
    TableRow {
        table: INBOUND_FRAMES,
        key: inbound_frame_key(connection_id, event_id),
        value: frame_bytes,
    }
}

pub fn inbound_frame_prefix(connection_id: ConnectionId) -> Vec<u8> {
    connection_id.to_vec()
}

pub fn decode_inbound_frame_work(
    key: Vec<u8>,
    frame_bytes: Vec<u8>,
) -> Result<InboundFrameWork, String> {
    if key.len() != 64 {
        return Err("sync inbound frame key must be 64 bytes".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&key[..32]);
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&key[32..]);
    Ok(InboundFrameWork {
        connection_id,
        event_id,
        frame_bytes,
    })
}

fn inbound_frame_key(connection_id: ConnectionId, event_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&connection_id);
    key.extend_from_slice(&event_id);
    key
}

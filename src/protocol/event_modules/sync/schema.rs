//! Sync-owned work tables.
//!
//! Sync compare/have/need are connection-scoped protocol events. Outgoing-scoped
//! events project into the connection outbox by id because they are already
//! answers ready for wrapping. Incoming-scoped events project here instead: the
//! projector records that the sync worker has stateful comparison work to do,
//! and the worker later drains these rows by connection.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::types::EventId;

pub const INBOUND_EVENTS: TableName = TableName::new("sync.inbound_events");

pub const SCHEMAS: &[Schema] = &[Schema::temp_row_table(
    "sync.inbound_events.v1",
    INBOUND_EVENTS,
)];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSyncEvent {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
    pub event_bytes: Vec<u8>,
}

impl InboundSyncEvent {
    pub fn key(&self) -> Vec<u8> {
        inbound_event_key(self.connection_id, self.event_id)
    }
}

pub fn inbound_event_row(
    connection_id: ConnectionId,
    event_id: EventId,
    event_bytes: Vec<u8>,
) -> TableRow {
    TableRow {
        table: INBOUND_EVENTS,
        key: inbound_event_key(connection_id, event_id),
        value: event_bytes,
    }
}

pub fn inbound_event_prefix(connection_id: ConnectionId) -> Vec<u8> {
    connection_id.to_vec()
}

pub fn decode_inbound_event(
    key: Vec<u8>,
    event_bytes: Vec<u8>,
) -> Result<InboundSyncEvent, String> {
    if key.len() != 64 {
        return Err("sync inbound event key must be 64 bytes".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&key[..32]);
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&key[32..]);
    Ok(InboundSyncEvent {
        connection_id,
        event_id,
        event_bytes,
    })
}

fn inbound_event_key(connection_id: ConnectionId, event_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&connection_id);
    key.extend_from_slice(&event_id);
    key
}

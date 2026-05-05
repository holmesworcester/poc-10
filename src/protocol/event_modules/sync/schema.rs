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
pub const CONNECTION_ACTIVITY: TableName = TableName::new("sync.connection_activity");

pub const SCHEMAS: &[Schema] = &[
    Schema::memory_row_table("sync.inbound_events.v1", INBOUND_EVENTS),
    Schema::memory_row_table("sync.connection_activity.v1", CONNECTION_ACTIVITY),
];

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

pub fn connection_activity_row(connection_id: ConnectionId, last_activity_ms: u64) -> TableRow {
    TableRow {
        table: CONNECTION_ACTIVITY,
        key: connection_id.to_vec(),
        value: last_activity_ms.to_be_bytes().to_vec(),
    }
}

pub fn decode_connection_activity(bytes: &[u8]) -> Result<u64, String> {
    let raw: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "sync activity row must be 8 bytes".to_string())?;
    Ok(u64::from_be_bytes(raw))
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

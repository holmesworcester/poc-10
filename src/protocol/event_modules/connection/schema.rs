//! Connection-owned row tables.
//!
//! `CONNECTION_EVENTS` stores canonical request/ack bytes that are needed to
//! validate later connection facts. `CONNECTIONS` maps established connection
//! ids to remote endpoints. `OUTBOX` is the protocol queue of inner event bytes
//! awaiting connection wrapping; core network queues only see the wrapped bytes
//! produced later by the worker.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

use super::types::{ConnectionId, OutboxKey};

pub const CONNECTION_EVENTS: TableName = TableName::new("connection.connection_events");
pub const CONNECTIONS: TableName = TableName::new("connection.connections");
pub const OUTBOX: TableName = TableName::new("connection.outbox");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("connection.connection_events.v1", CONNECTION_EVENTS),
    Schema::durable_row_table("connection.connections.v1", CONNECTIONS),
    Schema::durable_row_table("connection.outbox.v1", OUTBOX),
];

pub(crate) fn connection_event_row(event_id: EventId, bytes: Vec<u8>) -> TableRow {
    TableRow {
        table: CONNECTION_EVENTS,
        key: event_id.to_vec(),
        value: bytes,
    }
}

pub(crate) fn connection_row(connection_id: ConnectionId, remote_endpoint: EndpointId) -> TableRow {
    TableRow {
        table: CONNECTIONS,
        key: connection_id.to_vec(),
        value: remote_endpoint.to_vec(),
    }
}

pub fn outbox_row(
    connection_id: ConnectionId,
    event_id: EventId,
    canonical_bytes: Vec<u8>,
) -> TableRow {
    let key = OutboxKey {
        connection_id,
        event_id,
    }
    .to_bytes();
    TableRow {
        table: OUTBOX,
        key,
        value: canonical_bytes,
    }
}

//! Connection-owned row tables.
//!
//! `CONNECTION_EVENTS` stores canonical request/response bytes that are needed to
//! validate later connection facts. `CONNECTIONS` maps established connection
//! ids to remote endpoints. `CONNECTION_SCOPED_EVENTS` is an in-memory byte
//! cache for non-durable connection-scoped events such as sync compare/have/need.
//! `TRANSPORT_TARGETS` is receive-derived local state: connection projection
//! writes the latest socket address observed for a connection, but the address
//! is not a separate semantic event. Worker-owned send queues live in
//! `src/workers/schema.rs`.

use std::net::SocketAddr;

use crate::core::store::Store;
use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

use super::types::ConnectionId;

pub(in crate::protocol::event_modules) const CONNECTION_EVENTS: TableName =
    TableName::new("connection.connection_events");
pub(crate) const CONNECTIONS: TableName = TableName::new("connection.connections");
pub(crate) const CONNECTION_SCOPED_EVENTS: TableName =
    TableName::new("connection.connection_scoped_events");
pub(crate) const TRANSPORT_TARGETS: TableName = TableName::new("connection.transport_targets");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("connection.connection_events.v1", CONNECTION_EVENTS),
    Schema::durable_row_table("connection.connections.v1", CONNECTIONS),
    Schema::durable_row_table("connection.transport_targets.v1", TRANSPORT_TARGETS),
    Schema::memory_row_table(
        "connection.connection_scoped_events.v1",
        CONNECTION_SCOPED_EVENTS,
    ),
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

pub(crate) fn transport_target_row(connection_id: ConnectionId, addr: SocketAddr) -> TableRow {
    TableRow {
        table: TRANSPORT_TARGETS,
        key: connection_id.to_vec(),
        value: addr.to_string().into_bytes(),
    }
}

pub(crate) fn connection_scoped_event_row(event_id: EventId, canonical_bytes: Vec<u8>) -> TableRow {
    TableRow {
        table: CONNECTION_SCOPED_EVENTS,
        key: event_id.to_vec(),
        value: canonical_bytes,
    }
}

pub(crate) fn remote_endpoint(
    store: &Store,
    connection_id: ConnectionId,
) -> Result<EndpointId, String> {
    let bytes = store
        .table_row(CONNECTIONS, &connection_id)
        .map_err(|err| format!("load connection: {err}"))?
        .ok_or_else(|| "unknown connection".to_string())?;
    endpoint_id_from_bytes(&bytes)
}

fn endpoint_id_from_bytes(bytes: &[u8]) -> Result<EndpointId, String> {
    id_from_bytes(bytes).map_err(|_| "stored endpoint id is malformed".to_string())
}

fn id_from_bytes(bytes: &[u8]) -> Result<EventId, String> {
    if bytes.len() != 32 {
        return Err("stored id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

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
/// Durable row recording the steady-state listener this endpoint advertises.
///
/// The daemon overwrites this row on every startup so connection commands run
/// from sibling CLI processes can read it and quote the address inside
/// outbound connection requests. Memory-only storage cannot work here: CLI
/// processes share the database file with the daemon but each opens its own
/// in-process memory tables, so a memory row written by the daemon would be
/// invisible to a sibling `accept`/`connect` invocation. Stale rows are
/// possible after a crash and a config change; the next daemon launch
/// overwrites them.
pub(crate) const LOCAL_LISTEN_ADDR: TableName = TableName::new("connection.local_listen_addr");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("connection.connection_events.v1", CONNECTION_EVENTS),
    Schema::durable_row_table("connection.connections.v1", CONNECTIONS),
    Schema::durable_row_table("connection.transport_targets.v1", TRANSPORT_TARGETS),
    Schema::memory_row_table(
        "connection.connection_scoped_events.v1",
        CONNECTION_SCOPED_EVENTS,
    ),
    Schema::durable_row_table("connection.local_listen_addr.v1", LOCAL_LISTEN_ADDR),
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

/// Single-row key used by `LOCAL_LISTEN_ADDR`.
pub(crate) const LOCAL_LISTEN_ADDR_KEY: &[u8] = b"";

pub(crate) fn local_listen_addr_row(addr: SocketAddr) -> TableRow {
    TableRow {
        table: LOCAL_LISTEN_ADDR,
        key: LOCAL_LISTEN_ADDR_KEY.to_vec(),
        value: addr.to_string().into_bytes(),
    }
}

pub(crate) fn local_listen_addr(store: &Store) -> Result<Option<SocketAddr>, String> {
    let Some(value) = store
        .table_row(LOCAL_LISTEN_ADDR, LOCAL_LISTEN_ADDR_KEY)
        .map_err(|err| format!("load local listen addr: {err}"))?
    else {
        return Ok(None);
    };
    let text = String::from_utf8(value)
        .map_err(|err| format!("local listen addr is not utf8: {err}"))?;
    text.parse::<SocketAddr>()
        .map(Some)
        .map_err(|err| format!("local listen addr is invalid: {err}"))
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

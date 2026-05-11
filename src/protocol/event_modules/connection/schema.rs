//! Connection-owned row tables.
//!
//! `CONNECTION_EVENTS` stores canonical request/connection bytes that are needed
//! to validate later connection facts and decrypt connection transit until TTL
//! purge removes them. `REQUEST_CONNECTIONS` maps an accepted request to the
//! connection event id that completed it. `CONNECTIONS` maps established
//! connection ids to remote endpoints. `CONNECTION_INVITE_WORKSPACES` records the one
//! workspace an invite-scoped request authorizes before mutual endpoint
//! membership has projected. `CONNECTION_SCOPED_EVENTS` is a durable local byte
//! cache for connection-scoped events such as sync compare/have/need; it is not
//! shared history and is eligible for TTL purge.
//! `TRANSPORT_TARGETS` is local route state: invite accept/connect paths write
//! the invite address for the resulting connection, but the address is not a
//! separate semantic event. Worker-owned send queues live in `src/workers/schema.rs`.

use std::net::SocketAddr;

use crate::core::store::Store;
use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

use super::types::ConnectionId;

pub(in crate::protocol::event_modules) const CONNECTION_EVENTS: TableName =
    TableName::new("connection.connection_events");
pub(crate) const REQUEST_CONNECTIONS: TableName = TableName::new("connection.request_connections");
pub(crate) const CONNECTIONS: TableName = TableName::new("connection.connections");
pub(crate) const CONNECTION_INVITE_WORKSPACES: TableName =
    TableName::new("connection.invite_workspaces");
pub(crate) const CONNECTION_SCOPED_EVENTS: TableName =
    TableName::new("connection.connection_scoped_events");
pub(crate) const TRANSPORT_TARGETS: TableName = TableName::new("connection.transport_targets");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("connection.connection_events.v1", CONNECTION_EVENTS),
    Schema::durable_row_table("connection.request_connections.v1", REQUEST_CONNECTIONS),
    Schema::durable_row_table("connection.connections.v1", CONNECTIONS),
    Schema::durable_row_table(
        "connection.invite_workspaces.v1",
        CONNECTION_INVITE_WORKSPACES,
    ),
    Schema::durable_row_table("connection.transport_targets.v1", TRANSPORT_TARGETS),
    Schema::durable_row_table(
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

pub(crate) fn request_connection_row(request_id: EventId, connection_id: ConnectionId) -> TableRow {
    TableRow {
        table: REQUEST_CONNECTIONS,
        key: request_id.to_vec(),
        value: connection_id.to_vec(),
    }
}

pub(crate) fn connection_row(connection_id: ConnectionId, remote_endpoint: EndpointId) -> TableRow {
    TableRow {
        table: CONNECTIONS,
        key: connection_id.to_vec(),
        value: remote_endpoint.to_vec(),
    }
}

pub(crate) fn connection_invite_workspace_row(
    connection_id: ConnectionId,
    workspace_id: EventId,
) -> TableRow {
    TableRow {
        table: CONNECTION_INVITE_WORKSPACES,
        key: connection_id.to_vec(),
        value: workspace_id.to_vec(),
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

pub(crate) fn connection_event(
    store: &Store,
    connection_id: ConnectionId,
) -> Result<Vec<u8>, String> {
    store
        .table_row(CONNECTION_EVENTS, &connection_id)
        .map_err(|err| format!("load connection event: {err}"))?
        .ok_or_else(|| "unknown connection event".to_string())
}

pub(crate) fn connection_id_for_request(
    store: &Store,
    request_id: EventId,
) -> Result<Option<ConnectionId>, String> {
    let Some(bytes) = store
        .table_row(REQUEST_CONNECTIONS, &request_id)
        .map_err(|err| format!("load request connection: {err}"))?
    else {
        return Ok(None);
    };
    id_from_bytes(&bytes).map(Some)
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

pub(crate) fn invite_workspace(
    store: &Store,
    connection_id: ConnectionId,
) -> Result<Option<EventId>, String> {
    let Some(bytes) = store
        .table_row(CONNECTION_INVITE_WORKSPACES, &connection_id)
        .map_err(|err| format!("load connection invite workspace: {err}"))?
    else {
        return Ok(None);
    };
    id_from_bytes(&bytes).map(Some)
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

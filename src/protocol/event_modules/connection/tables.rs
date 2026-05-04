use crate::core::store::{EventId, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

use super::types::{ConnectionId, OutboxKey};

pub const CONNECTION_EVENTS: &str = "connection.connection_events";
pub const CONNECTIONS: &str = "connection.connections";
pub const OUTBOX: &str = "connection.outbox";

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

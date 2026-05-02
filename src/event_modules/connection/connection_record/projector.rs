use crate::event_modules::identity::endpoint::types::EndpointId;
use crate::store::{EventId, ModuleRow};

use super::tables;
use super::types::ConnectionId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub rows: Vec<ModuleRow>,
    pub response: Option<Vec<u8>>,
    pub connection_id: Option<ConnectionId>,
}

pub(crate) fn connection_event_row(event_id: EventId, bytes: Vec<u8>) -> ModuleRow {
    ModuleRow {
        table: tables::CONNECTION_EVENTS,
        key: event_id.to_vec(),
        value: bytes,
    }
}

pub(crate) fn connection_row(
    connection_id: ConnectionId,
    remote_endpoint: EndpointId,
) -> ModuleRow {
    ModuleRow {
        table: tables::CONNECTIONS,
        key: connection_id.to_vec(),
        value: remote_endpoint.to_vec(),
    }
}

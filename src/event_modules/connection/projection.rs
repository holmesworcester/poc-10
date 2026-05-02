use std::net::SocketAddr;

use crate::store::{EventId, ModuleRow};

use super::tables;
use super::types::{ConnectionId, EndpointId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub rows: Vec<ModuleRow>,
    pub response: Option<Vec<u8>>,
    pub connection_id: Option<ConnectionId>,
}

pub fn local_endpoint(endpoint: EndpointId, secret: [u8; 32]) -> Projection {
    Projection {
        rows: vec![
            ModuleRow {
                table: tables::LOCAL_ENDPOINT,
                key: b"local".to_vec(),
                value: endpoint.to_vec(),
            },
            ModuleRow {
                table: tables::LOCAL_ENDPOINT_SECRET,
                key: b"local".to_vec(),
                value: secret.to_vec(),
            },
        ],
        response: None,
        connection_id: None,
    }
}

pub fn invite_secret(bootstrap_hash: [u8; 32], private_key: [u8; 32]) -> Projection {
    Projection {
        rows: vec![ModuleRow {
            table: tables::INVITE_SECRETS,
            key: bootstrap_hash.to_vec(),
            value: private_key.to_vec(),
        }],
        response: None,
        connection_id: None,
    }
}

pub fn transport_target(connection_id: ConnectionId, addr: SocketAddr) -> Projection {
    Projection {
        rows: vec![ModuleRow {
            table: tables::TRANSPORT_TARGETS,
            key: connection_id.to_vec(),
            value: addr.to_string().into_bytes(),
        }],
        response: None,
        connection_id: Some(connection_id),
    }
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

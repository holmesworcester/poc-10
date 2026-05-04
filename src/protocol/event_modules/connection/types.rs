//! Shared connection-domain types.
//!
//! The connection id is derived from the request id and accepting endpoint so
//! both sides can agree on it without another round trip.

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

pub type ConnectionId = [u8; 32];

pub(super) const EVENT_MAGIC: &[u8; 10] = b"TOPOCONN1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InboundConnection {
    pub outgoing: Vec<Vec<u8>>,
    pub connection_id: Option<ConnectionId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OutboxKey {
    pub(super) connection_id: ConnectionId,
    pub(super) event_id: EventId,
}

impl OutboxKey {
    pub(super) fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.connection_id);
        bytes.extend_from_slice(&self.event_id);
        bytes
    }
}

pub(super) fn connection_id(request_id: &EventId, from_endpoint: &EndpointId) -> ConnectionId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-connection-v1");
    hasher.update(request_id);
    hasher.update(from_endpoint);
    *hasher.finalize().as_bytes()
}

pub(super) fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

pub(in crate::protocol::event_modules) fn connection_id_from_bytes(
    bytes: &[u8],
) -> Result<ConnectionId, String> {
    bytes
        .try_into()
        .map_err(|_| "connection id must be 32 bytes".to_string())
}

pub(super) fn is_connection_event(bytes: &[u8]) -> bool {
    bytes.starts_with(EVENT_MAGIC)
}

use crate::store::EventId;

pub type EndpointId = [u8; 32];
pub type ConnectionId = [u8; 32];
pub type TransitNonce = [u8; 24];

pub const EVENT_MAGIC: &[u8; 10] = b"TOPOCONN1\0";

pub fn bootstrap_hash(token: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-bootstrap-token-v1");
    hasher.update(token.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn connection_id(request_id: &EventId, from_endpoint: &EndpointId) -> ConnectionId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-connection-v1");
    hasher.update(request_id);
    hasher.update(from_endpoint);
    *hasher.finalize().as_bytes()
}

pub fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

pub fn is_connection_event(bytes: &[u8]) -> bool {
    bytes.starts_with(EVENT_MAGIC)
}

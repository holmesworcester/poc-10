use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::protocol::connection::bootstrap_response::fact::BootstrapResponseFact;
use crate::protocol::connection::bootstrap_response::transit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapResponseSentFact {
    pub response_id: FactId,
    pub request_id: FactId,
    pub responder_ephemeral_secret_fact_id: FactId,
    pub peer_addr: SocketAddr,
    pub response: BootstrapResponseFact,
    pub sealed_response_bytes: [u8; transit::SEALED_CONNECTION_RESPONSE_BYTES],
    pub created_at_ms: u64,
}

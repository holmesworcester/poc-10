use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::protocol::connection::bootstrap_request::fact::BootstrapRequestFact;
use crate::protocol::connection::bootstrap_request::transit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRequestSentFact {
    pub request_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub peer_addr: SocketAddr,
    pub request: BootstrapRequestFact,
    pub sealed_request_bytes: [u8; transit::SEALED_CONNECTION_REQUEST_BYTES],
    pub created_at_ms: u64,
}

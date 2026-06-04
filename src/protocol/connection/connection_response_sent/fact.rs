use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::protocol::connection::connection_response::{fact::ConnectionResponseFact, layout};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionResponseSentFact {
    pub response_id: FactId,
    pub request_id: FactId,
    pub responder_ephemeral_secret_fact_id: FactId,
    pub peer_addr: SocketAddr,
    pub response: ConnectionResponseFact,
    pub sealed_response_bytes: [u8; layout::SEALED_FACT_BYTES],
    pub created_at_ms: u64,
}

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::protocol::connection::connection_request::{fact::ConnectionRequestFact, layout};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequestSentFact {
    pub request_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub peer_addr: SocketAddr,
    pub request: ConnectionRequestFact,
    pub sealed_request_bytes: [u8; layout::SEALED_FACT_BYTES],
    pub created_at_ms: u64,
}

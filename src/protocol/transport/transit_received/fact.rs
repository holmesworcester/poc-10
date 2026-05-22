//! Local transport::transit receive provenance facts.
//!
//! A `TransitReceivedFact` is a local about-fact for one received shared fact.
//! It records observational receive metadata and projects a context offer keyed
//! by `received_fact_id`; it does not validate or authorize the received fact.
//! `origin_addr` is stored as canonical `SocketAddr::to_string()` bytes.

use crate::core::facts::FactId;

pub const ORIGIN_ADDR_BYTES: usize = 256;
pub const TRANSIT_KIND_BOOTSTRAP: u8 = 0;
pub const TRANSIT_KIND_CONNECTION: u8 = 1;
pub const TRANSIT_KIND_CONNECTION_HANDSHAKE: u8 = 2;

pub type EndpointId = FactId;
pub type ConnectionId = FactId;
pub type RequestId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitReceivedFact {
    pub received_fact_id: FactId,
    pub origin_addr: Vec<u8>,
    pub local_endpoint_id: EndpointId,
    pub sender_endpoint_id: EndpointId,
    pub transit_kind: u8,
    pub connection_id: Option<ConnectionId>,
    pub request_id: Option<RequestId>,
    pub frame_hash: [u8; 32],
    pub received_at_local_ms: u64,
}

impl TransitReceivedFact {
    pub fn origin_addr_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.origin_addr)
    }
}

use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEstablishedFact {
    pub connection_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub responder_ephemeral_secret_fact_id: FactId,
    pub responder_ephemeral_public_key: EndpointId,
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
    pub established_at_ms: u64,
}

//! Membership connection-response payload.
//!
//! A response completes a membership handshake and is the local connection
//! fact: its fact id is the connection id and its body carries the
//! `connection_secret` used to open established frames. The secret is derived
//! from Diffie-Hellman only — there is no invite material on this path.

use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionResponseFact {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub responder_ephemeral_secret_fact_id: FactId,
    pub responder_ephemeral_public_key: EndpointId,
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}

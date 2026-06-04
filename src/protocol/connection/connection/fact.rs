//! Unified connection payload.
//!
//! A connection completes a bootstrap or membership handshake. Its fact id is
//! the connection id, and its body carries the `connection_secret` used to open
//! established frames.

use std::net::SocketAddr;

use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionFact {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: FactId,
    pub responder_addr: Option<SocketAddr>,
    pub initiator_addr: Option<SocketAddr>,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub responder_ephemeral_secret_fact_id: FactId,
    pub responder_ephemeral_public_key: EndpointId,
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}

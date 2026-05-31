//! Membership connection-request payload.
//!
//! A connection request is first contact with an endpoint that *already knows
//! us*: it is authorized by membership, not an invite. It names the initiator
//! and target endpoints, carries a nonce, pins the initiator's `endpoint_shared`
//! membership fact id and ephemeral material, and carries an endpoint signature
//! over the handshake transcript made with the initiator's endpoint signing key.
//! It carries no invite material.
//!
//! The payload is the semantic request body before projection. Projection proves
//! the signature against the initiator's `endpoint_shared` signing key and a
//! shared workspace; it parks if that membership is not yet held locally.

use std::net::SocketAddr;

use crate::core::crypto::Ed25519Signature;
use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequestFact {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub nonce: [u8; 32],
    /// Initiator's `endpoint_shared` membership fact id (the membership witness).
    pub initiator_endpoint_shared_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub initiator_ephemeral_public_key: EndpointId,
    /// Ed25519 signature over the request transcript by the initiator endpoint
    /// signing key (validated against `initiator_endpoint_shared` signing key).
    pub endpoint_signature: Ed25519Signature,
    pub from_listen_addr: Option<SocketAddr>,
    pub to_listen_addr: Option<SocketAddr>,
}

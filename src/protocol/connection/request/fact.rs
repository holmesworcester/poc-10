//! Unified connection-request payload.
//!
//! A request is the single sealed first-contact fact for both bootstrap and
//! membership handshakes. `mode` selects which authorization branch is active:
//! bootstrap requests carry invite proof fields, membership requests carry
//! endpoint-shared proof fields. All fields are present in the fixed layout; the
//! inactive branch must be zeroed so the byte shape is deterministic.

use std::net::SocketAddr;

use crate::core::crypto::Ed25519Signature;
use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];

pub const REQUEST_MODE_BOOTSTRAP: u8 = 1;
pub const REQUEST_MODE_MEMBERSHIP: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequestFact {
    pub mode: u8,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub nonce: [u8; 32],
    /// Address the initiator actually dialed for this connection attempt.
    pub dialed_addr: Option<SocketAddr>,
    /// Address the initiator can receive the response on for this connection.
    pub initiator_addr: Option<SocketAddr>,
    /// Bootstrap-mode invite fact id. Zero in membership mode.
    pub invite_fact_id: FactId,
    /// Bootstrap-mode invite bootstrap hash. Zero in membership mode.
    pub bootstrap_hash: [u8; 32],
    /// Bootstrap-mode local invite-secret fact id. Zero in membership mode.
    pub invite_secret_fact_id: FactId,
    /// Bootstrap-mode signature over the request transcript. Zero in membership mode.
    pub invite_signature: Ed25519Signature,
    /// Membership-mode `endpoint_shared` membership fact id. Zero in bootstrap mode.
    pub initiator_endpoint_shared_id: FactId,
    /// Membership-mode endpoint signature over the request transcript. Zero in bootstrap mode.
    pub endpoint_signature: Ed25519Signature,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub initiator_ephemeral_public_key: EndpointId,
}

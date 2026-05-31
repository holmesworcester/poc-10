//! Connection-request payload.
//!
//! A request names the initiator and target endpoints, carries a nonce and
//! invite signature over the handshake transcript, pins invite/secret
//! dependency fact ids, records the initiator ephemeral public key, and may
//! include listen-address hints for both sides.
//!
//! The payload is the semantic request body before projection. It does not
//! prove the invite, receipt, or local secret by itself; `project.rs` matches
//! those context witnesses and decides which branch can materialize.

use std::net::SocketAddr;

use crate::core::crypto::Ed25519Signature;
use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapRequestFact {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub nonce: [u8; 32],
    pub invite_fact_id: FactId,
    pub bootstrap_hash: [u8; 32],
    pub invite_signature: Ed25519Signature,
    pub invite_secret_fact_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub initiator_ephemeral_public_key: EndpointId,
    pub from_listen_addr: Option<SocketAddr>,
    pub to_listen_addr: Option<SocketAddr>,
}

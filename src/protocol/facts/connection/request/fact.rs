//! Connection-request fact shape for the poc-10 target tree.
//!
//! The request names both endpoints, carries a transcript-bound invite
//! signature, and pins the dependency edges that bootstrap authorisation will
//! validate. The optional listen address is the requester's advertised
//! steady-state listener, used by transport::transit handlers as a route hint after the
//! bootstrap stream closes.
//!
//! This fact is the canonical body of a connection request. Signed-envelope
//! wrapping is owned by the `identity::signed_fact` module and is wired in a later wave.

use std::net::SocketAddr;

use crate::core::crypto::Ed25519Signature;
use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequestFact {
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

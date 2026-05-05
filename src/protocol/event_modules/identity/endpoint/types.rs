//! Local endpoint types.
//!
//! Endpoint ids are X25519 public keys used for transit. Endpoints also carry a
//! distinct Ed25519 signing key used by shared events that are authorized by an
//! endpoint's workspace membership. Both private keys are local-only facts.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointKeypair {
    pub endpoint: EndpointId,
    pub secret: [u8; 32],
    pub signing_public_key: Ed25519PublicKey,
    pub signing_secret: Ed25519PrivateKey,
}

//! Connection ephemeral-secret fact shape for the poc-10 target tree.
//!
//! This is a local-only fact: it carries an X25519 private key that bootstraps
//! a connection handshake for a single endpoint. The matching public key is
//! also recorded so projection can validate the pair without re-deriving it.

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEphemeralSecretFact {
    pub owner_endpoint: EndpointId,
    pub ephemeral_private_key: X25519PrivateKey,
    pub ephemeral_public_key: X25519PublicKey,
    pub created_at_ms: u64,
}

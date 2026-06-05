//! Connection ephemeral-secret fact payload.
//!
//! The payload records the endpoint that owns the handshake secret, the X25519
//! private key, the matching public key, and the local creation time. It is
//! valid only as a local fact; the projector checks that the public key derives
//! from the private key before offering the secret as context.
//!
//! Keep this file to the typed payload shape. Byte layout belongs in
//! `encode.rs`/`decode.rs`, row storage belongs in the family manifest's row
//! schema, and admission policy belongs in `project.rs`.

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEphemeralSecretFact {
    pub owner_endpoint: EndpointId,
    pub ephemeral_private_key: X25519PrivateKey,
    pub ephemeral_public_key: X25519PublicKey,
    pub created_at_ms: u64,
}

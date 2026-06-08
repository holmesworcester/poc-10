//! Local signer-secret fact shape.
//!
//! This local fact stores the private Ed25519 material for one signer id in a
//! workspace. The public key must match the private key, and projection exposes
//! only local context. Signature evidence creation belongs to command
//! projector, not to this fact family.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::FactId;

pub type SignerId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSignerSecretFact {
    pub workspace_id: FactId,
    pub signer_id: SignerId,
    pub public_key: Ed25519PublicKey,
    pub private_key: Ed25519PrivateKey,
}

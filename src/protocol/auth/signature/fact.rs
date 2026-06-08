//! Semantic signature evidence fact shape.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::core::facts::FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFact {
    pub workspace_id: FactId,
    pub created_at_ms: u64,
    pub target_fact_id: FactId,
    pub signer_public_key: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

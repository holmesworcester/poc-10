//! User fact shape for workspace identity.
//!
//! A user fact is the durable identity record for a human account inside a
//! workspace: timestamp, workspace id, signing public key, and display name.
//! It does not describe devices or endpoint membership; those live in endpoint
//! and invite fact families. Keep only protocol payload fields here.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub const USERNAME_BYTES: usize = 64;

pub type UserId = FactId;
pub type WorkspaceId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserFact {
    pub created_at_ms: u64,
    pub workspace_id: WorkspaceId,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

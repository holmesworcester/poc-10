//! User fact shape for workspace identity.
//!
//! A user fact is the durable identity record for a human account inside a
//! workspace: timestamp, workspace id, signing public key, and display name.
//! It does not describe devices or endpoint membership; those live in endpoint
//! and invite fact families. Keep only protocol payload fields here.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::core::wire::FixedText;

pub const USERNAME_BYTES: usize = 64;

pub type UserId = FactId;
pub type WorkspaceId = FactId;
pub type Username = FixedText<USERNAME_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserFact {
    pub created_at_ms: u64,
    pub workspace_id: WorkspaceId,
    pub public_key: Ed25519PublicKey,
    pub username: Username,
    pub signer_id: FactId,
    pub signer_public_key: Ed25519PublicKey,
}

//! User fact shape for the poc-10 target tree.

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

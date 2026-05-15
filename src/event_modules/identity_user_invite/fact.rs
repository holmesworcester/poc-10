//! User-invite fact shape for the poc-10 target tree.
//!
//! A user-invite fact publishes an invite public key bound to one workspace
//! and records the authority event that endorsed it. The private invite key
//! travels out-of-band and is not projected as shared state.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInviteFact {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: WorkspaceId,
    pub authority_event_id: FactId,
}

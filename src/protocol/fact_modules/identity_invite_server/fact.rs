//! Invite-server fact shape for the poc-10 target tree.
//!
//! An invite-server fact publishes an invite public key for one workspace and
//! records the authority event that endorsed it. The private invite secret is
//! intentionally absent.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteServerFact {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: WorkspaceId,
    pub authority_event_id: FactId,
}

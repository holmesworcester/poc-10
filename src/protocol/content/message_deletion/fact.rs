//! Content-message-deletion fact shape for the poc-10 target tree.
//!
//! A message deletion is a workspace-scoped declaration that the named
//! `author_user_id` wants `target_message_id` removed. The target frontier and
//! minute are the deletion match coordinate used by content and key projectors;
//! the target message validates that coordinate and author before it self-purges.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;
pub type SignerId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMessageDeletionFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub target_message_id: FactId,
    pub target_frontier_id: FactId,
    pub target_minute: u64,
    pub author_user_id: AuthorId,
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
}

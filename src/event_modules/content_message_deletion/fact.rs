//! Content-message-deletion fact shape for the poc-10 target tree.
//!
//! A message deletion is a workspace-scoped declaration that the named
//! `author_user_id` wants `target_message_id` removed. The projector validates
//! that the target message belongs to the same workspace and was authored by
//! that user before it materializes deletion state.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMessageDeletionFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub target_message_id: FactId,
    pub author_user_id: AuthorId,
}

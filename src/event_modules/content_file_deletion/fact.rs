//! Content-file-deletion fact shape for the poc-10 target tree.
//!
//! A file deletion is a workspace-scoped, author-bound declaration that the
//! named `author_user_id` wants the file fact identified by
//! `target_file_id` removed. The canonical fact body carries only the public
//! envelope (workspace, timestamp, target, author); if the fact is carried in a
//! signed envelope, the projector validates the signature after the signer
//! context proves endpoint authority for the named author.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileDeletionFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub target_file_id: FactId,
    pub author_user_id: AuthorId,
}

//! Content-file-deletion fact shape for the poc-10 target tree.
//!
//! A file deletion is a workspace-scoped, author-bound declaration that the
//! named `author_user_id` wants the file fact identified by
//! `target_file_id` removed. The canonical fact body carries only the public
//! envelope (workspace, timestamp, target, author, signer, signature).
//!
//! Current boundary: signature verification and signer-to-author authority live
//! in the file-deletion projector with auth context witnesses.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;
pub type SignerId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileDeletionFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub target_file_id: FactId,
    pub author_user_id: AuthorId,
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

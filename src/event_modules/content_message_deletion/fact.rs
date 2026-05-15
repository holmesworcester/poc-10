//! Content-message-deletion fact shape for the poc-10 target tree.
//!
//! A message deletion is a workspace-scoped, author-bound declaration that the
//! named `author_user_id` wants `target_message_id` removed. The canonical fact
//! body carries only the public envelope (workspace, timestamp, target,
//! author); the signed envelope around this payload lives in the `signed_fact`
//! event module and is intentionally not represented here. This is the public-
//! shape author-authorization shape; the sealed-message layer's separate
//! `MessageDeletionFact` carries the local-projection retire coordinates.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Legacy validates a signed envelope binding an endpoint_shared signer to
//!   the named author; the target signed-fact envelope and identity
//!   dependency context are separate event modules and not consulted here.

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

//! Read-only structs over content-message-deletion projection rows.
//!
//! Rows are keyed by `workspace_id || target_message_id` so the per-message
//! purge cascade can be authorized against the message's own author without a
//! secondary index. The value carries the deletion fact id, created_at_ms, and
//! deletion author. Per-message purge orchestration (frontier coords, retire
//! walks) lives in a separate handler and is deferred.

use crate::core::facts::FactId;

use super::fact::{AuthorId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionRow {
    pub workspace_id: WorkspaceId,
    pub target_message_id: FactId,
    pub deletion_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
}

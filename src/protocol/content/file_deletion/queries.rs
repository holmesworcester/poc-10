//! Read-only queries over content-file-deletion projections.
//!
//! Deletion rows are keyed by `workspace_id || target_file_id` so the per-file
//! purge cascade can be authorized against the file's own author without a
//! secondary index. The value carries the deletion fact id, created_at_ms, and
//! deletion author. This file holds the row shape consumers read; it never
//! decides whether a deletion should be admitted.

use crate::core::facts::FactId;

use super::fact::{AuthorId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDeletionRow {
    pub workspace_id: WorkspaceId,
    pub target_file_id: FactId,
    pub deletion_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
}

//! Retired unsealed content-message fact shape.
//!
//! Normal poc-10 chat messages are encrypted sealed-message facts. This module
//! is not registered by the concrete protocol; it exists only for older
//! migration fixtures that have not been rewritten yet.

use crate::core::facts::FactId;

pub const UNIX_MINUTE_MS: u64 = 60_000;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;
pub type FrontierId = FactId;

/// Retired public-shape content-message fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMessageFact {
    pub workspace_id: WorkspaceId,
    pub author_user_id: AuthorId,
    pub created_at_ms: u64,
    pub frontier_id: FrontierId,
    pub minute: u64,
    pub leaf_id: FactId,
    pub sealed_body_ref: FactId,
}

/// Convenience: derive the authoring `unix_minute` from `created_at_ms`. The
/// fact carries `minute` explicitly so peers do not have to recompute, but
/// admission helpers may want to compare.
pub fn unix_minute_for(created_at_ms: u64) -> u64 {
    created_at_ms / UNIX_MINUTE_MS
}

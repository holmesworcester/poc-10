//! Sync fact shape for making one fact shareable in a workspace.
//!
//! A `SharedFact` is the durable declaration that a fact belongs in the sync
//! index for a workspace. It does not copy the fact bytes. Projection records a
//! row that later lets connection-specific sync decide which peers are allowed
//! to receive the named fact.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedFact {
    pub workspace_id: WorkspaceId,
    pub fact_id: FactId,
}

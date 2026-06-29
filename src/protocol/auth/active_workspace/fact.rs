//! Active-workspace fact shape.
//!
//! A single local-only selection of the workspace this store's commands default
//! to. `effective_at_ms` lets projection keep the latest selection wins.

use crate::core::facts::FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveWorkspaceFact {
    pub effective_at_ms: u64,
    pub workspace_id: FactId,
}

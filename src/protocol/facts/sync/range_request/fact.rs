//! Sync fact shape for requesting a timestamp range on one connection.
//!
//! Range requests are protocol control facts. They name the workspace,
//! connection, and inclusive timestamp interval the peer should consider, while
//! leaving response planning to the compare and transport intent handlers.
//! Layout validation guarantees only that the range is well formed.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type ConnectionId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRangeRequestFact {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub start: u64,
    pub end: u64,
}

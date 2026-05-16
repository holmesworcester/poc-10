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

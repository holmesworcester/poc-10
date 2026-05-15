//! Poc-10 sync context fact shapes.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type ConnectionId = FactId;
pub type EventId = FactId;
pub type KeyWrapId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRangeRequestFact {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedRootFact {
    pub workspace_id: WorkspaceId,
    pub event_id: EventId,
    pub dependency_id: EventId,
    pub key_wrap_id: KeyWrapId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedEventFact {
    pub workspace_id: WorkspaceId,
    pub event_id: EventId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyWrapAvailableFact {
    pub workspace_id: WorkspaceId,
    pub key_wrap_id: KeyWrapId,
}

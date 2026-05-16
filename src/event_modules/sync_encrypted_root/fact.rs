use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type EventId = FactId;
pub type KeyWrapId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedRootFact {
    pub workspace_id: WorkspaceId,
    pub event_id: EventId,
    pub dependency_id: EventId,
    pub key_wrap_id: KeyWrapId,
}

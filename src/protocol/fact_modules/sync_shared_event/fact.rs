use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type EventId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedEventFact {
    pub workspace_id: WorkspaceId,
    pub event_id: EventId,
}

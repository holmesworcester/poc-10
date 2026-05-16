use crate::core::facts::FactId;

pub type WorkspaceId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedFact {
    pub workspace_id: WorkspaceId,
    pub fact_id: FactId,
}

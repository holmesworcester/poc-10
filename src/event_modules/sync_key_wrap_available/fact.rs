use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type KeyWrapId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyWrapAvailableFact {
    pub workspace_id: WorkspaceId,
    pub key_wrap_id: KeyWrapId,
}

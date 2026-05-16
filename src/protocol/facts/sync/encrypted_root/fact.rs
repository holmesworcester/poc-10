use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type KeyWrapId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedRootFact {
    pub workspace_id: WorkspaceId,
    pub fact_id: FactId,
    pub dependency_id: FactId,
    pub key_wrap_id: KeyWrapId,
}

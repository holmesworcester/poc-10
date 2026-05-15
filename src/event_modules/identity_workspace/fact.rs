//! Workspace root fact shape for the poc-10 target tree.

use crate::core::facts::FactId;

pub const WORKSPACE_NAME_BYTES: usize = 64;

pub type WorkspaceId = FactId;
pub type WorkspacePublicKey = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceFact {
    pub created_at_ms: u64,
    pub public_key: WorkspacePublicKey,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRow {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub public_key: WorkspacePublicKey,
    pub name: String,
}

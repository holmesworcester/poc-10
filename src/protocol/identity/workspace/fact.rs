//! Workspace root fact shape.
//!
//! A workspace fact creates the identity namespace that users, endpoints,
//! invites, encryption policy, and sync sharing attach to. It contains only the
//! stable public fields needed to name that namespace. Membership, roles, and
//! local secrets are modeled by separate fact families.

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

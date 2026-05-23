//! Local secret-retirement fact shape.
//!
//! The fact names the local secret-source being retired and records the local
//! policy reason that produced the retirement context.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type SecretId = FactId;

pub const RETIRE_REASON_CHOP: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalSecretRetirementFact {
    pub workspace_id: WorkspaceId,
    pub target_secret_id: SecretId,
    pub reason_kind: u8,
    pub floor_minute: u64,
    pub created_at_ms: u64,
}

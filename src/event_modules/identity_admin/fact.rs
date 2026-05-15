//! Admin grant fact shape for the poc-10 target tree.
//!
//! An admin grant binds a public key to administrative authority within a single
//! workspace. Bootstrap grants name the workspace itself as both authority and
//! user; ongoing grants name a prior admin fact as authority and a user fact as
//! the target binding.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub type AdminId = FactId;
pub type UserId = FactId;
pub type WorkspaceId = FactId;
pub type AdminPublicKey = Ed25519PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminFact {
    pub created_at_ms: u64,
    pub workspace_id: WorkspaceId,
    pub public_key: AdminPublicKey,
    pub authority_fact_id: FactId,
    pub user_fact_id: UserId,
}

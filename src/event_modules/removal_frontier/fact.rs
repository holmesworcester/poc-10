//! Removal frontier fact shape for the poc-10 target tree.
//!
//! A removal frontier is the workspace-scoped authorization point for a content
//! key. The frontier id is the fact id; key secrets and key wraps name
//! `removal_frontier_id` directly. The list of `removal_fact_ids` is a compact
//! frontier set (not a full history list) whose dependency closure represents
//! removals incorporated by this frontier. The field is fixed-width on the
//! wire; commands split unusually large concurrent removals into multiple
//! frontier facts.
//!
//! The legacy module under `src/protocol/event_modules/encryption/` carried a
//! signed envelope wrapping the payload plus admin/endpoint_shared dependency
//! checks. The target tree does not yet have signed-envelope or admin
//! projectors at this layer, so the target module accepts the raw fact and
//! validates the body shape only. This will be tightened in the Wave 6
//! reconciliation.
//!
//! `workspace_id` is the workspace fact id; `authority_admin_id` names the
//! admin grant whose user is presumed to authorise the frontier.

use crate::core::facts::FactId;

pub const MAX_REMOVAL_FACT_REFS: usize = 4;

pub type WorkspaceId = FactId;
pub type RemovalFrontierId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub authority_admin_id: FactId,
    pub removal_fact_ids: Vec<FactId>,
}

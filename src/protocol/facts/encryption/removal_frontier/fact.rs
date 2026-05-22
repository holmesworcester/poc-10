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
//! `workspace_id` is the workspace fact id; `authority_admin_id` names the
//! admin grant whose user authorizes the frontier. Projection waits for that
//! admin context and for every referenced removal fact before publishing the
//! frontier row and context offers.

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

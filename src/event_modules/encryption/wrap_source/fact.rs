//! Removal-frontier fact shape (wrap-source root).

use super::super::recipient_key::fact::{EndpointId, WorkspaceId};
use crate::core::facts::FactId;

pub type FrontierId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierFact {
    pub workspace_id: WorkspaceId,
    pub owner_endpoint_id: EndpointId,
    pub created_at_ms: u64,
}

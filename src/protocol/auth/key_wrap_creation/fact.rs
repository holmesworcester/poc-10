//! Key-wrap creation fact shape.
//!
//! The fact is a local instruction to produce one deterministic `key_wrap`
//! fact from exact local source and signer material.

use crate::core::facts::FactId;
use crate::protocol::auth::key_wrap::fact::WrapSourceKind;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type EndpointId = FactId;
pub type RecipientKeyId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapCreationFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub recipient_key_id: RecipientKeyId,
    pub source_fact_id: FactId,
    pub signer_secret_fact_id: FactId,
    pub owner_endpoint_id: EndpointId,
    pub frontier_created_at_ms: u64,
    pub source: WrapSourceKind,
}

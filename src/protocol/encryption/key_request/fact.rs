//! Key request fact shape.
//!
//! A key request asks an endpoint that owns a removal frontier to produce a
//! wrap for a requester recipient key.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type EndpointId = FactId;
pub type RecipientKeyId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestFact {
    pub workspace_id: WorkspaceId,
    pub requester_endpoint_id: EndpointId,
    pub responder_endpoint_id: EndpointId,
    pub frontier_id: FrontierId,
    pub recipient_key_id: RecipientKeyId,
    pub created_at_ms: u64,
}

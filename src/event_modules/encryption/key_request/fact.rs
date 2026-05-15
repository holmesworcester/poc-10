//! Key-request fact shape.

use super::super::recipient_key::fact::{EndpointId, RecipientKeyId, WorkspaceId};
use super::super::wrap_source::fact::FrontierId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestFact {
    pub workspace_id: WorkspaceId,
    pub requester_endpoint_id: EndpointId,
    pub responder_endpoint_id: EndpointId,
    pub frontier_id: FrontierId,
    pub recipient_key_id: RecipientKeyId,
    pub created_at_ms: u64,
}

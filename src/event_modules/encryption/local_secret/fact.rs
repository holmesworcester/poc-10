//! Local frontier-root and history-node secret fact shapes.

use super::super::recipient_key::fact::{EndpointId, WorkspaceId};
use super::super::wrap_source::fact::FrontierId;
use crate::core::crypto::XChaCha20Poly1305Key;
use crate::core::facts::FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeySecretFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub owner_endpoint_id: EndpointId,
    pub created_at_ms: u64,
    pub key_secret: XChaCha20Poly1305Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub owner_endpoint_id: EndpointId,
    pub source_secret_id: FactId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub event_id_prefix: FactId,
    pub tombstone_node_id: FactId,
    pub node_secret: XChaCha20Poly1305Key,
}

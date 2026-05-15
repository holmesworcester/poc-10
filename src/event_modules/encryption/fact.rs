//! Poc-10 encryption fact shapes for key healing and wrap materialization.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type EndpointId = FactId;
pub type RecipientKeyId = FactId;

pub const NO_PREVIOUS_RECIPIENT_KEY: FactId = [0; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyFact {
    pub workspace_id: WorkspaceId,
    pub endpoint_id: EndpointId,
    pub recipient_key: FactId,
    pub previous_recipient_key_id: FactId,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierFact {
    pub workspace_id: WorkspaceId,
    pub owner_endpoint_id: EndpointId,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeySecretFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub owner_endpoint_id: EndpointId,
    pub created_at_ms: u64,
    pub secret_commitment: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub source_secret_id: FactId,
    pub start_minute: u64,
    pub end_minute: u64,
    pub prefix_bytes: u8,
    pub leaf_prefix: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestFact {
    pub workspace_id: WorkspaceId,
    pub requester_endpoint_id: EndpointId,
    pub responder_endpoint_id: EndpointId,
    pub frontier_id: FrontierId,
    pub recipient_key_id: RecipientKeyId,
    pub created_at_ms: u64,
}

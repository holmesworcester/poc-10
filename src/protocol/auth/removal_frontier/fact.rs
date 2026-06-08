//! Removal frontier fact shape.
//!
//! A removal frontier names the endpoint that owns the root key secret for a
//! workspace key tree. Projection proves the owning endpoint before the fact
//! becomes usable frontier context.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type EndpointId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierFact {
    pub workspace_id: WorkspaceId,
    pub owner_endpoint_id: EndpointId,
    pub created_at_ms: u64,
    pub signer_public_key: Ed25519PublicKey,
}

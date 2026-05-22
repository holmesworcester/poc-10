//! Local key secret fact shape.
//!
//! A local key secret is private store material for a removal frontier's root
//! key. Projection ties it to its frontier and publishes wrap-source and
//! secret-coverage offers.

use crate::core::crypto::XChaCha20Poly1305Key;
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type EndpointId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeySecretFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub owner_endpoint_id: EndpointId,
    pub created_at_ms: u64,
    pub key_secret: XChaCha20Poly1305Key,
}

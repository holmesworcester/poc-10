//! Recipient key fact shape.
//!
//! A recipient key names an endpoint public key that can receive workspace
//! auth key material. It may supersede a previous recipient key for the same
//! endpoint. Layout fixes the wire bytes; projection validates supersession.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type EndpointId = FactId;

pub const NO_PREVIOUS_RECIPIENT_KEY: FactId = [0; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyFact {
    pub workspace_id: WorkspaceId,
    pub endpoint_id: EndpointId,
    pub recipient_key: FactId,
    pub previous_recipient_key_id: FactId,
    pub created_at_ms: u64,
    pub signer_public_key: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

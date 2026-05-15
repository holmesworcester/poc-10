//! Recipient-key fact shapes (public recipient keys and their local secrets).

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
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
pub struct LocalRecipientKeyFact {
    pub workspace_id: WorkspaceId,
    pub recipient_key_id: RecipientKeyId,
    pub recipient_key: X25519PublicKey,
    pub recipient_secret: X25519PrivateKey,
}

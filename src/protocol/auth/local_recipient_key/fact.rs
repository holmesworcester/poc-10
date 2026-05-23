//! Local recipient key fact shape.
//!
//! A local recipient key holds the private X25519 material that lets this store
//! unwrap key wraps addressed to a recipient public key. Projection proves it
//! matches the shared recipient fact.

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type RecipientKeyId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecipientKeyFact {
    pub workspace_id: WorkspaceId,
    pub recipient_key_id: RecipientKeyId,
    pub recipient_key: X25519PublicKey,
    pub recipient_secret: X25519PrivateKey,
}

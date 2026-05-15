//! Key-wrap fact shape and wrapped-secret kinds.

use super::super::recipient_key::fact::{EndpointId, RecipientKeyId, WorkspaceId};
use super::super::wrap_source::fact::FrontierId;
use crate::core::crypto::{X25519PublicKey, XChaCha20Poly1305Nonce};
use crate::core::facts::FactId;

pub const KEY_WRAP_CIPHERTEXT_BYTES: usize = 48;

pub type KeyWrapCiphertext = [u8; KEY_WRAP_CIPHERTEXT_BYTES];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedSecretKind {
    FrontierRoot,
    HistoryNode,
}

impl WrappedSecretKind {
    pub fn as_u8(self) -> u8 {
        match self {
            WrappedSecretKind::FrontierRoot => 0,
            WrappedSecretKind::HistoryNode => 1,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(WrappedSecretKind::FrontierRoot),
            1 => Ok(WrappedSecretKind::HistoryNode),
            _ => Err("unknown wrapped secret kind".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub signer_endpoint_id: EndpointId,
    pub frontier_id: FrontierId,
    pub wrapped_secret_kind: WrappedSecretKind,
    pub wrapped_secret_id: FactId,
    pub wrapped_source_secret_id: FactId,
    pub wrapped_tombstone_node_id: FactId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub event_id_prefix: FactId,
    pub recipient_key_id: RecipientKeyId,
    pub sender_wrap_public_key: X25519PublicKey,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: KeyWrapCiphertext,
}

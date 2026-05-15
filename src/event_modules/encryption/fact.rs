//! Poc-10 encryption fact shapes for key healing and wrap materialization.

use crate::core::crypto::{X25519PublicKey, XChaCha20Poly1305Key, XChaCha20Poly1305Nonce};
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type EndpointId = FactId;
pub type RecipientKeyId = FactId;

pub const NO_PREVIOUS_RECIPIENT_KEY: FactId = [0; 32];
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestFact {
    pub workspace_id: WorkspaceId,
    pub requester_endpoint_id: EndpointId,
    pub responder_endpoint_id: EndpointId,
    pub frontier_id: FrontierId,
    pub recipient_key_id: RecipientKeyId,
    pub created_at_ms: u64,
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

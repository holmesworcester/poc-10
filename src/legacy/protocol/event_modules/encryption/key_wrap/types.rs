//! Key-wrap event types.
//!
//! A key wrap is a shared fact for one recipient key and one removal frontier.
//! It carries sealed key-secret bytes plus the event id the receiver must
//! recreate as a local key-secret event after opening the wrap.

use crate::core::crypto::{
    Ed25519PublicKey, Ed25519Signature, X25519PublicKey, XChaCha20Poly1305Nonce,
};
use crate::legacy::protocol::event_modules::types::EventId;

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
pub struct KeyWrapEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub removal_frontier_id: EventId,
    pub wrapped_secret_kind: WrappedSecretKind,
    pub wrapped_secret_id: EventId,
    pub wrapped_source_secret_id: EventId,
    pub wrapped_tombstone_node_id: EventId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub event_id_prefix: EventId,
    pub recipient_key_id: EventId,
    pub sender_wrap_public_key: X25519PublicKey,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: KeyWrapCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKeyWrapEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapRow {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub recipient_key_id: EventId,
    pub key_wrap_id: EventId,
    pub created_at_ms: u64,
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub wrapped_secret_kind: WrappedSecretKind,
    pub wrapped_secret_id: EventId,
    pub wrapped_source_secret_id: EventId,
    pub wrapped_tombstone_node_id: EventId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub event_id_prefix: EventId,
    pub sender_wrap_public_key: X25519PublicKey,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: KeyWrapCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingKeyUnwrapRow {
    pub key: Vec<u8>,
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub recipient_key_id: EventId,
    pub key_wrap_id: EventId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingWrapReconcileKind {
    RecipientKey,
    Frontier,
}

impl PendingWrapReconcileKind {
    pub fn as_u8(self) -> u8 {
        match self {
            PendingWrapReconcileKind::RecipientKey => 1,
            PendingWrapReconcileKind::Frontier => 2,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(PendingWrapReconcileKind::RecipientKey),
            2 => Ok(PendingWrapReconcileKind::Frontier),
            _ => Err("unknown pending wrap reconcile kind".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWrapReconcileRow {
    pub key: Vec<u8>,
    pub workspace_id: EventId,
    pub kind: PendingWrapReconcileKind,
    pub target_id: EventId,
}

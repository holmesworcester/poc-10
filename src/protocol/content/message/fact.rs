//! Semantic content-message fact shape.
//!
//! The fact type is public protocol metadata. User-visible message text is an
//! encrypted field that opens only when matching key context is available.

use crate::core::crypto::{Ed25519PublicKey, XCHACHA20_POLY1305_TAG_BYTES};
use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub const UNIX_MINUTE_MS: u64 = 60_000;
pub const CIPHERTEXT_BYTES: usize = 128;
pub const NONCE_BYTES: usize = 24;
pub const TEXT_LENGTH_PREFIX_BYTES: usize = 4;
pub const PLAINTEXT_SLOT_BYTES: usize = CIPHERTEXT_BYTES - XCHACHA20_POLY1305_TAG_BYTES;
pub const MAX_TEXT_BYTES: usize = PLAINTEXT_SLOT_BYTES - TEXT_LENGTH_PREFIX_BYTES;
pub type MessageCiphertext = FixedSlot<CIPHERTEXT_BYTES>;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;
pub type FrontierId = FactId;
pub type SignerId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMessageFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
    pub frontier_id: FrontierId,
    pub local_history_node_secret_id: FactId,
    pub expires_at_minute: u64,
    pub retention_policy_id: FactId,
    pub minute: u64,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: MessageCiphertext,
}

/// Convenience: derive the authoring `unix_minute` from `created_at_ms`. The
/// fact carries `minute` explicitly so peers do not have to recompute, but
/// admission helpers may want to compare.
pub fn unix_minute_for(created_at_ms: u64) -> u64 {
    created_at_ms / UNIX_MINUTE_MS
}

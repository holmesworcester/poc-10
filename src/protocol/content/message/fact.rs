//! Semantic content-message fact shape.
//!
//! The fact type is public protocol metadata. User-visible message text is an
//! encrypted field that opens only when matching key context is available.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub const UNIX_MINUTE_MS: u64 = 60_000;
pub const CIPHERTEXT_BYTES: usize = 128;
pub const NONCE_BYTES: usize = 24;
pub type MessageCiphertext = FixedSlot<CIPHERTEXT_BYTES>;

// ----- Canonical wire schema (shared by encode.rs and decode.rs) -----

pub const TYPE_CONTENT_MESSAGE: u8 = 50;

/// Total fixed wire width of an encoded content-message fact.
pub const CONTENT_MESSAGE_BYTES: usize = 1
    + 32
    + 8
    + 32
    + 32
    + 32
    + 32
    + 32
    + 8
    + 32
    + 8
    + NONCE_BYTES
    + 4
    + CIPHERTEXT_BYTES
    + crate::core::crypto::ED25519_SIGNATURE_BYTES;

/// Offset of the trailing signature field; the signing transcript zeroes it.
pub const SIGNATURE_OFFSET: usize =
    CONTENT_MESSAGE_BYTES - crate::core::crypto::ED25519_SIGNATURE_BYTES;

// Encrypted text slot layout (plaintext is length-prefixed, then padded).
pub const TEXT_LENGTH_PREFIX_BYTES: usize = 4;
pub const PLAINTEXT_SLOT_BYTES: usize =
    CIPHERTEXT_BYTES - crate::core::crypto::XCHACHA20_POLY1305_TAG_BYTES;
pub const MAX_TEXT_BYTES: usize = PLAINTEXT_SLOT_BYTES - TEXT_LENGTH_PREFIX_BYTES;

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
    pub signature: Ed25519Signature,
}

/// Convenience: derive the authoring `unix_minute` from `created_at_ms`. The
/// fact carries `minute` explicitly so peers do not have to recompute, but
/// admission helpers may want to compare.
pub fn unix_minute_for(created_at_ms: u64) -> u64 {
    created_at_ms / UNIX_MINUTE_MS
}

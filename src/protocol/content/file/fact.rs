//! Content-file fact shape for the poc-10 target tree.
//!
//! A file descriptor is a workspace-scoped, message-attached metadata fact
//! naming a file's encrypted blob. The public envelope carries the workspace,
//! parent message, author, file id, blob byte count, slice budget, and the
//! BLAKE3 root hash of the encrypted blob (carried in plaintext per the design
//! note in `README.md`). Filename, mime, and other descriptor secrets
//! ride inside an opaque `sealed_metadata` slot encrypted with the parent
//! message content key.
//!
//! Descriptor secrecy is limited to the opaque sealed metadata slot here; CLI
//! display resolves the parent message key before opening it. Signature
//! authority belongs to the content-file projector, and per-slice BAO
//! verification belongs to the content-file-slice projector.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;
pub type SignerId = FactId;

/// BLAKE3 root hash of the encrypted blob, carried in plaintext.
pub const FILE_ROOT_HASH_BYTES: usize = 32;
pub const SEALED_METADATA_BYTES: usize = 512;
pub type RootHash = [u8; FILE_ROOT_HASH_BYTES];
pub type SealedMetadata = FixedSlot<SEALED_METADATA_BYTES>;

/// Product hard cap on declared blob size.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub message_id: FactId,
    pub author_user_id: AuthorId,
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
    pub file_id: FactId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: RootHash,
    /// Opaque sealed descriptor metadata (filename + mime + AEAD tag).
    pub sealed_metadata: SealedMetadata,
    pub signature: Ed25519Signature,
}

//! Content-file fact shape for the poc-10 target tree.
//!
//! A file descriptor is a workspace-scoped, message-attached metadata event
//! naming a file's encrypted blob. The public envelope carries the workspace,
//! parent message, author, file id, blob byte count, slice budget, and the
//! BLAKE3 root hash of the encrypted blob (carried in plaintext per the design
//! note in `new_architecture.md`). Filename, mime, and other descriptor secrets
//! ride inside an opaque `sealed_metadata` slot whose AEAD framing is owned by
//! auth key-material code in a later wave.
//!
//! Current boundaries:
//! - Signed envelope verification is owned by `auth::signed_fact`.
//! - Descriptor secrecy is limited to the opaque sealed metadata slot here;
//!   key selection and per-file content-key context belong to the auth
//!   wave.
//! - Slice integrity is checked by the file-slice admit pipeline.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;

/// BLAKE3 root hash of the encrypted blob, carried in plaintext.
pub const FILE_ROOT_HASH_BYTES: usize = 32;
pub type RootHash = [u8; FILE_ROOT_HASH_BYTES];

/// Product hard cap on declared blob size.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub message_id: FactId,
    pub author_user_id: AuthorId,
    pub file_id: FactId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: RootHash,
    /// Opaque sealed descriptor metadata (filename + mime + AEAD tag). Treated
    /// as an opaque byte blob in this slice; auth key-material code owns the
    /// inner framing in a later wave.
    pub sealed_metadata: Vec<u8>,
}

//! Content-file fact shape for the poc-10 target tree.
//!
//! A file descriptor is a workspace-scoped, message-attached metadata event
//! naming a file's encrypted blob. The public envelope carries the workspace,
//! parent message, author, file id, blob byte count, slice budget, and the
//! BLAKE3 root hash of the encrypted blob (carried in plaintext per the design
//! note in `new_architecture.md`). Filename, mime, and other descriptor secrets
//! ride inside an opaque `sealed_metadata` slot whose AEAD framing is owned by
//! the encryption module in a later wave.
//!
//! Deferred (legacy parity gaps):
//! - Signed-fact envelope wrapping (separate event module).
//! - Per-file leaf-coordinate derivation and content-key context — the
//!   `local_history_node_secret_id` and frontier id will land with the
//!   per-message FS wave.
//! - Bao proof verification for slices (see `content_file_slice`).

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;

/// BLAKE3 root hash of the encrypted blob, carried in plaintext.
pub const FILE_ROOT_HASH_BYTES: usize = 32;
pub type RootHash = [u8; FILE_ROOT_HASH_BYTES];

/// Hard cap on declared blob size. Mirrors the legacy 10 GiB ceiling.
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
    /// as an opaque byte blob in this slice; the encryption module owns the
    /// inner framing in a later wave.
    pub sealed_metadata: Vec<u8>,
}

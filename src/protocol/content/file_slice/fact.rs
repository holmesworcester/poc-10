//! Content-file-slice fact shape for the poc-10 target tree.
//!
//! Each slice carries one chunk of an encrypted file blob, identified by its
//! parent `file_id` and `slice_index`. The slice ciphertext is treated as an
//! opaque length-prefixed blob; auth key-material code owns the AEAD framing
//! and per-slice nonce derivation in a later wave.
//!
//! Current boundaries:
//! - Signed envelope verification is owned by `auth::signed_envelope`.
//! - Slice proof material is handled by the file-send/admit path, not this
//!   narrow fact shape.
//! - Parent-descriptor existence is enforced by the admit pipeline before
//!   projection materializes rows.

use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub type WorkspaceId = FactId;
pub const FILE_SLICE_CIPHERTEXT_BYTES: usize = 256 * 1024;
pub type FileSliceCiphertext = FixedSlot<FILE_SLICE_CIPHERTEXT_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub file_id: FactId,
    pub slice_index: u32,
    /// Opaque per-slice ciphertext. Encryption framing and the per-slice nonce
    /// are owned by auth key-material code in a later wave.
    pub ciphertext: FileSliceCiphertext,
}

//! Content-file-slice fact shape for the poc-10 target tree.
//!
//! Each slice carries one chunk of an encrypted file blob, identified by its
//! parent `file_id` and `slice_index`. The slice ciphertext is treated as an
//! opaque length-prefixed blob; send-file/save-file own the AEAD framing and
//! deterministic per-slice nonce derivation.
//!
//! Current boundaries:
//! - Signed envelope verification is owned by `auth::signed_fact`.
//! - Slice proof material is handled by the file-send/admit path, not this
//!   narrow fact shape.
//! - Parent-descriptor existence is enforced by the admit pipeline before
//!   projection materializes rows.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub file_id: FactId,
    pub slice_index: u32,
    /// Opaque per-slice ciphertext.
    pub ciphertext: Vec<u8>,
}

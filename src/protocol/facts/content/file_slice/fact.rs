//! Content-file-slice fact shape for the poc-10 target tree.
//!
//! Each slice carries one chunk of an encrypted file blob, identified by its
//! parent `file_id` and `slice_index`. The slice ciphertext is treated as an
//! opaque length-prefixed blob; the encryption module owns the AEAD framing
//! and per-slice nonce derivation in a later wave.
//!
//! Deferred (legacy parity gaps):
//! - Signed-fact envelope wrapping (separate fact module).
//! - Bao proof slot — legacy carries a fixed-width BAO proof verified against
//!   the parent descriptor's root hash. The target tree will reintroduce this
//!   slot once the file-send command wave can compute proofs.
//! - Parent-descriptor existence check on admission (depends on file_rows
//!   projection ordering — handled by the admit pipeline, not this projector).

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub file_id: FactId,
    pub slice_index: u32,
    /// Opaque per-slice ciphertext. Encryption framing and the per-slice nonce
    /// are owned by the encryption module in a later wave.
    pub ciphertext: Vec<u8>,
}

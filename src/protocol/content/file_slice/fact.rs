//! Content-file-slice fact shape for the poc-10 target tree.
//!
//! Each slice carries a self-contained BAO proof for one encrypted file-blob
//! range, identified by its parent `file_id` and `slice_index`. Projection
//! verifies the proof against the parent file root hash, extracts the encrypted
//! slice bytes, and only then counts the slice as received.
//!
//! Signature authority belongs to the content-file-slice projector. Slice proof
//! material is handled by the file-send/admit path, and parent-descriptor
//! existence is enforced before projection materializes rows.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature, XCHACHA20_POLY1305_TAG_BYTES};
use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub type WorkspaceId = FactId;
pub type SignerId = FactId;
pub const FILE_SLICE_PLAINTEXT_BYTES: usize = 256 * 1024;
pub const FILE_SLICE_CIPHERTEXT_BYTES: usize =
    FILE_SLICE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
/// poc-7 measured a 17 KiB BAO encoding budget for 256 KiB slices under the
/// 10 GiB file cap. Poc-10 proves encrypted slices, so keep a larger fixed
/// margin while preserving predictable frame sizing.
pub const FILE_SLICE_BAO_PROOF_OVERHEAD_BYTES: usize = 64 * 1024;
pub const FILE_SLICE_BAO_PROOF_BYTES: usize =
    FILE_SLICE_CIPHERTEXT_BYTES + FILE_SLICE_BAO_PROOF_OVERHEAD_BYTES;
pub type FileSliceProof = FixedSlot<FILE_SLICE_BAO_PROOF_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub file_id: FactId,
    pub slice_index: u32,
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
    /// BAO slice proof whose verified payload is the encrypted slice bytes.
    pub proof: FileSliceProof,
    pub signature: Ed25519Signature,
}

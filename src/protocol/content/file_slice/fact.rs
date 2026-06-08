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

use crate::core::crypto::{Ed25519PublicKey, XCHACHA20_POLY1305_TAG_BYTES};
use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub type WorkspaceId = FactId;
pub type SignerId = FactId;
pub const FILE_SLICE_PLAINTEXT_BYTES: usize = 256 * 1024;
pub const FILE_SLICE_CIPHERTEXT_BYTES: usize =
    FILE_SLICE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const BAO_CHUNK_BYTES: usize = 1024;
const BAO_HEADER_BYTES: usize = 8;
const BAO_PARENT_NODE_BYTES: usize = 64;

const fn div_ceil_u64(value: u64, divisor: u64) -> u64 {
    (value + divisor - 1) / divisor
}

const fn div_ceil_usize(value: usize, divisor: usize) -> usize {
    (value + divisor - 1) / divisor
}

const fn ceil_log2_u64(value: u64) -> usize {
    let mut bits = 0;
    let mut rest = value.saturating_sub(1);
    while rest > 0 {
        bits += 1;
        rest >>= 1;
    }
    bits
}

const MAX_FILE_SLICE_COUNT: u64 = div_ceil_u64(MAX_FILE_BYTES, FILE_SLICE_PLAINTEXT_BYTES as u64);
const MAX_FILE_CIPHERTEXT_BYTES: u64 =
    MAX_FILE_BYTES + MAX_FILE_SLICE_COUNT * XCHACHA20_POLY1305_TAG_BYTES as u64;
const MAX_FILE_BAO_CHUNKS: u64 = div_ceil_u64(MAX_FILE_CIPHERTEXT_BYTES, BAO_CHUNK_BYTES as u64);
const MAX_FILE_BAO_TREE_DEPTH: usize = ceil_log2_u64(MAX_FILE_BAO_CHUNKS);
const FILE_SLICE_BAO_ROUNDED_CHUNKS: usize =
    div_ceil_usize(FILE_SLICE_CIPHERTEXT_BYTES, BAO_CHUNK_BYTES) + 1;
const FILE_SLICE_BAO_MAX_PARENT_NODES: usize =
    (FILE_SLICE_BAO_ROUNDED_CHUNKS - 1) + (2 * MAX_FILE_BAO_TREE_DEPTH);

/// Fixed BAO proof slot for every encrypted file-slice fact.
///
/// Poc-7 sized this from BAO's real layout instead of guessing a large field:
/// 256 KiB plaintext slices under the 10 GiB file cap needed 17_352 bytes of
/// BAO overhead. Poc-10 proves the encrypted blob instead, so every full slice
/// is 16 bytes longer and slice starts move through all 1 KiB BAO chunk
/// alignments. The bound below covers:
///
/// - the encrypted slice rounded out to BAO chunk boundaries,
/// - the internal parent nodes for that rounded range,
/// - both authentication paths through the deepest supported 10 GiB tree,
/// - the BAO slice header.
pub const FILE_SLICE_BAO_PROOF_BYTES: usize = FILE_SLICE_BAO_ROUNDED_CHUNKS * BAO_CHUNK_BYTES
    + FILE_SLICE_BAO_MAX_PARENT_NODES * BAO_PARENT_NODE_BYTES
    + BAO_HEADER_BYTES;
pub const FILE_SLICE_BAO_PROOF_OVERHEAD_BYTES: usize =
    FILE_SLICE_BAO_PROOF_BYTES - FILE_SLICE_CIPHERTEXT_BYTES;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;

    #[test]
    fn bao_slot_budget_covers_all_encrypted_slice_alignments() {
        let encrypted_blob = vec![0x42; FILE_SLICE_CIPHERTEXT_BYTES * 65];
        let (root_hash, outboard) = crypto::bao_outboard(&encrypted_blob).expect("outboard");

        for slice_index in 0..64 {
            let slice_start = (slice_index * FILE_SLICE_CIPHERTEXT_BYTES) as u64;
            let proof = crypto::bao_extract_slice(
                &encrypted_blob,
                &outboard,
                slice_start,
                FILE_SLICE_CIPHERTEXT_BYTES as u64,
            )
            .expect("extract slice");

            assert!(
                proof.len() <= FILE_SLICE_BAO_PROOF_BYTES,
                "slice {slice_index} proof is {} bytes, slot is {} bytes",
                proof.len(),
                FILE_SLICE_BAO_PROOF_BYTES
            );
            FileSliceProof::new(&proof).expect("proof fits fixed slot");
            let verified = crypto::bao_verify_slice(
                &root_hash,
                &proof,
                slice_start,
                FILE_SLICE_CIPHERTEXT_BYTES as u64,
            )
            .expect("proof verifies");
            assert_eq!(verified.len(), FILE_SLICE_CIPHERTEXT_BYTES);
        }
    }

    #[test]
    fn bao_slot_budget_is_sized_from_the_max_supported_file_tree() {
        assert_eq!(MAX_FILE_SLICE_COUNT, 40_960);
        assert_eq!(MAX_FILE_BAO_TREE_DEPTH, 24);
        assert!(FILE_SLICE_BAO_PROOF_OVERHEAD_BYTES > 17 * 1024);
        assert!(FILE_SLICE_BAO_PROOF_OVERHEAD_BYTES < 32 * 1024);
    }
}

//! Content-file-slice fact shape for the poc-10 target tree.
//!
//! Each slice carries one chunk of an encrypted file blob, identified by its
//! parent `file_id` and `slice_index`. The slice ciphertext is treated as an
//! opaque length-prefixed blob; send-file/save-file own the AEAD framing and
//! deterministic per-slice nonce derivation.
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
pub type FileSliceCiphertext = FixedSlot<FILE_SLICE_CIPHERTEXT_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub file_id: FactId,
    pub slice_index: u32,
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
    /// Opaque per-slice ciphertext.
    pub ciphertext: FileSliceCiphertext,
    pub signature: Ed25519Signature,
}

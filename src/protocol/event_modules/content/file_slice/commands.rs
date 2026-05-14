//! Commands for creating file slices.
//!
//! `create` takes a pre-built BAO slice proof, the descriptor's event id, and
//! the descriptor's `local_history_node_secret_id`. `slice_from_ciphertext` is the
//! convenience wrapper send-file uses with the full encrypted blob and its
//! BAO outboard already in hand. Both produce one signed file slice event
//! whose projection verifies the slice's ciphertext bytes against the
//! descriptor's `root_hash`.

use crate::core::crypto::{
    self, Ed25519PrivateKey, XChaCha20Poly1305Key, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::{BuildSlice, FileSliceEvent, FILE_SLICE_DATA_BYTES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFileSlice {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub file_id: EventId,
    pub file_event_id: EventId,
    pub slice_number: u32,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub local_history_node_secret_id: EventId,
    pub plaintext_len: u32,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFileSliceOutput {
    pub slice_event_id: EventId,
    pub file_id: EventId,
    pub slice_number: u32,
}

pub fn create(input: CreateFileSlice) -> Result<CommandOutput<CreateFileSliceOutput>, String> {
    let event = FileSliceEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        file_id: input.file_id,
        slice_number: input.slice_number,
        local_history_node_secret_id: input.local_history_node_secret_id,
        plaintext_len: input.plaintext_len,
        proof: input.proof,
    };
    let payload = codec::encode(&event, &input.file_event_id)?;
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes_signed = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes_signed)?;
    let slice_event_id = crate::protocol::event_modules::types::event_id(&record.canonical_bytes);
    Ok(CommandOutput::with_events(
        CreateFileSliceOutput {
            slice_event_id,
            file_id: event.file_id,
            slice_number: event.slice_number,
        },
        vec![record],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceFromCiphertext<'a> {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub file_id: EventId,
    pub file_event_id: EventId,
    pub slice_number: u32,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub local_history_node_secret_id: EventId,
    pub plaintext_len: u32,
    /// Concatenated per-slice ciphertexts; this is the byte stream BAO is
    /// computed over, so any slice proof verifies against the descriptor's
    /// encrypted-blob root hash.
    pub ciphertext: &'a [u8],
    pub outboard: &'a [u8],
    pub slice_start: u64,
    pub slice_len: u64,
}

pub fn slice_from_ciphertext(
    input: SliceFromCiphertext<'_>,
) -> Result<CommandOutput<CreateFileSliceOutput>, String> {
    let event = codec::build_slice(BuildSlice {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        file_id: input.file_id,
        slice_number: input.slice_number,
        local_history_node_secret_id: input.local_history_node_secret_id,
        plaintext_len: input.plaintext_len,
        ciphertext: input.ciphertext,
        outboard: input.outboard,
        slice_start: input.slice_start,
        slice_len: input.slice_len,
    })?;
    create(CreateFileSlice {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        file_id: input.file_id,
        file_event_id: input.file_event_id,
        slice_number: input.slice_number,
        signer_endpoint_shared_id: input.signer_endpoint_shared_id,
        signer_private_key: input.signer_private_key,
        local_history_node_secret_id: input.local_history_node_secret_id,
        plaintext_len: input.plaintext_len,
        proof: event.proof,
    })
}

/// Result of `seal_file_blob`: per-slice ciphertext stream, BAO root and
/// outboard tree over that stream, plus the constants the caller needs
/// when authoring per-slice events.
pub struct SealedFileBlob {
    /// Concatenated per-slice ciphertexts in slice order.
    pub ciphertext: Vec<u8>,
    /// BAO root hash for `ciphertext`; goes into the file descriptor.
    pub root_hash: [u8; 32],
    /// BAO outboard for `ciphertext`; used to produce per-slice proofs.
    pub outboard: Vec<u8>,
    /// Number of slices the blob was split into.
    pub total_slices: u32,
    /// Bytes per slice (last slice may be shorter).
    pub slice_bytes: u32,
    /// Plaintext-length per slice (last slice may be shorter than
    /// `slice_bytes` if the blob did not divide evenly).
    pub plaintext_lengths: Vec<u32>,
}

impl SealedFileBlob {
    /// Offset (in bytes) into `ciphertext` where slice `slice_number`
    /// begins. Equal to `slice_number * (slice_bytes + AEAD_TAG)`.
    pub fn slice_start(&self, slice_number: u32) -> u64 {
        let chunk_size = u64::from(self.slice_bytes) + XCHACHA20_POLY1305_TAG_BYTES as u64;
        u64::from(slice_number) * chunk_size
    }

    /// Length (in bytes) of slice `slice_number`'s ciphertext.
    pub fn slice_len(&self, slice_number: u32) -> u64 {
        let plaintext_len = u64::from(self.plaintext_lengths[slice_number as usize]);
        plaintext_len + XCHACHA20_POLY1305_TAG_BYTES as u64
    }
}

/// Encrypt a file plaintext under `leaf_node_secret` into per-slice
/// ciphertexts and compute the BAO outboard over those ciphertexts.
/// Returns the ciphertext stream, BAO root, outboard tree, and the
/// slice-shape constants. The caller still authors the descriptor event
/// (using `root_hash`) and per-slice events (using
/// `slice_from_ciphertext`).
pub fn seal_file_blob(
    leaf_node_secret: &XChaCha20Poly1305Key,
    workspace_id: &EventId,
    file_id: &EventId,
    signer_endpoint_shared_id: &EventId,
    plaintext: &[u8],
) -> Result<SealedFileBlob, String> {
    let blob_bytes = plaintext.len() as u64;
    let slice_bytes = u32::try_from(FILE_SLICE_DATA_BYTES)
        .map_err(|_| "slice budget overflows u32".to_string())?;
    let total_slices = if blob_bytes == 0 {
        0u32
    } else {
        u32::try_from(plaintext.len().div_ceil(FILE_SLICE_DATA_BYTES))
            .map_err(|_| "slice count overflows u32".to_string())?
    };
    let mut ciphertext = Vec::with_capacity(
        plaintext.len() + (total_slices as usize) * XCHACHA20_POLY1305_TAG_BYTES,
    );
    let mut plaintext_lengths = Vec::with_capacity(total_slices as usize);
    for slice_number in 0..total_slices {
        let start = (slice_number as usize) * slice_bytes as usize;
        let end = ((slice_number + 1) as usize * slice_bytes as usize).min(plaintext.len());
        plaintext_lengths.push((end - start) as u32);
        let chunk = codec::seal_slice(
            leaf_node_secret,
            workspace_id,
            file_id,
            slice_number,
            signer_endpoint_shared_id,
            &plaintext[start..end],
        )?;
        ciphertext.extend_from_slice(&chunk);
    }
    let (root_hash, outboard) = if ciphertext.is_empty() {
        ([0u8; 32], Vec::new())
    } else {
        crypto::bao_outboard(&ciphertext)?
    };
    Ok(SealedFileBlob {
        ciphertext,
        root_hash,
        outboard,
        total_slices,
        slice_bytes,
        plaintext_lengths,
    })
}

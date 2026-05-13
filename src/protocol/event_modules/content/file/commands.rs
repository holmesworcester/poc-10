//! Commands for creating file descriptor events.
//!
//! Commands choose canonical event content and return proposed events; they do
//! not write descriptor rows, slice rows, or worker queues. The caller must
//! supply already-decided identity, signing, file_id, and BAO root facts plus
//! the parent message's content key (`(removal_frontier_id,
//! local_history_node_secret_id, key_secret)`). The descriptor's sensitive fields —
//! filename and mime — are sealed under that key with a fresh
//! XChaCha20-Poly1305 nonce and domain-separated AAD before the event leaves
//! the command boundary; root_hash, blob byte length, and slice arithmetic
//! stay in clear so the slice pipeline can verify BAO proofs without holding
//! a key.

use crate::core::crypto::{self, Ed25519PrivateKey, Hash, XChaCha20Poly1305Key};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::{
    FileDescriptorCiphertext, FileDescriptorPlaintext, FileEvent, FILE_DESCRIPTOR_CIPHERTEXT_BYTES,
    MAX_FILE_BYTES,
};

/// Sanity guard: non-zero ids, size cap, and consistent slice arithmetic.
/// The codec is intentionally lenient on decode; this helper is shared
/// between the authoring path and the receive projector so a malformed
/// peer event is rejected at projection time too.
pub(super) fn validate_event_fields(event: &FileEvent) -> Result<(), String> {
    if event.blob_bytes > MAX_FILE_BYTES {
        return Err("file size exceeds the 10 GiB limit".to_string());
    }
    validate_id("file workspace", &event.workspace_id)?;
    validate_id("file message_id", &event.message_id)?;
    validate_id("file author_user_id", &event.author_user_id)?;
    validate_id("file file_id", &event.file_id)?;
    validate_id("file removal_frontier_id", &event.removal_frontier_id)?;
    validate_id(
        "file local_history_node_secret_id",
        &event.local_history_node_secret_id,
    )?;
    if event.blob_bytes == 0 {
        if event.total_slices != 0 {
            return Err("zero-byte file must declare zero slices".to_string());
        }
        return Ok(());
    }
    if event.total_slices == 0 {
        return Err("non-empty file must declare at least one slice".to_string());
    }
    if event.slice_bytes == 0 {
        return Err("non-empty file must declare a slice budget".to_string());
    }
    let expected = expected_slice_count(event.blob_bytes, event.slice_bytes as u64)?;
    if expected != event.total_slices {
        return Err(format!(
            "total_slices {} does not match blob_bytes / slice_bytes ceiling {}",
            event.total_slices, expected
        ));
    }
    Ok(())
}

fn expected_slice_count(blob_bytes: u64, slice_bytes: u64) -> Result<u32, String> {
    if slice_bytes == 0 {
        return Err("slice_bytes must be non-zero".to_string());
    }
    let count = blob_bytes.div_ceil(slice_bytes);
    u32::try_from(count).map_err(|_| "slice count overflows u32".to_string())
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFile {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub message_id: EventId,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub file_id: EventId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: Hash,
    pub filename: String,
    pub mime_type: String,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub key_secret: XChaCha20Poly1305Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFileOutput {
    pub file_event_id: EventId,
    pub file_id: EventId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: Hash,
    pub filename: String,
    pub mime_type: String,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
}

pub fn create(input: CreateFile) -> Result<CommandOutput<CreateFileOutput>, String> {
    let mut event = FileEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        message_id: input.message_id,
        author_user_id: input.author_user_id,
        file_id: input.file_id,
        blob_bytes: input.blob_bytes,
        total_slices: input.total_slices,
        slice_bytes: input.slice_bytes,
        root_hash: input.root_hash,
        removal_frontier_id: input.removal_frontier_id,
        local_history_node_secret_id: input.local_history_node_secret_id,
        nonce: crypto::random_xchacha20poly1305_nonce(),
        ciphertext: [0; FILE_DESCRIPTOR_CIPHERTEXT_BYTES],
    };
    validate_event_fields(&event)?;
    let plaintext = FileDescriptorPlaintext {
        filename: input.filename.clone(),
        mime_type: input.mime_type.clone(),
    };
    let aad = codec::descriptor_associated_data(&event, input.signer_endpoint_shared_id);
    let ciphertext: FileDescriptorCiphertext =
        codec::seal_descriptor_slot(&input.key_secret, &event.nonce, &aad, &plaintext)?;
    event.ciphertext = ciphertext;

    let payload = codec::encode(&event)?;
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let file_event_id = crate::protocol::event_modules::types::event_id(&record.canonical_bytes);
    Ok(CommandOutput::with_events(
        CreateFileOutput {
            file_event_id,
            file_id: event.file_id,
            blob_bytes: event.blob_bytes,
            total_slices: event.total_slices,
            slice_bytes: event.slice_bytes,
            root_hash: input.root_hash,
            filename: input.filename,
            mime_type: input.mime_type,
            removal_frontier_id: event.removal_frontier_id,
            local_history_node_secret_id: event.local_history_node_secret_id,
        },
        vec![record],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make() -> CreateFile {
        CreateFile {
            workspace_id: [1; 32],
            created_at_ms: 10,
            message_id: [2; 32],
            author_user_id: [3; 32],
            signer_endpoint_shared_id: [4; 32],
            signer_private_key: [5; 32],
            file_id: [6; 32],
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 1024,
            root_hash: [7; 32],
            filename: "secret-name.bin".to_string(),
            mime_type: "application/x-secret".to_string(),
            removal_frontier_id: [8; 32],
            local_history_node_secret_id: [9; 32],
            key_secret: [42; 32],
        }
    }

    #[test]
    fn create_proposes_signed_descriptor_without_plaintext_filename_or_mime() {
        let output = create(make()).expect("create");
        let record = output.events[0].record();
        let canonical = &record.canonical_bytes;
        assert!(!canonical
            .windows("secret-name.bin".len())
            .any(|w| w == b"secret-name.bin"));
        assert!(!canonical
            .windows("application/x-secret".len())
            .any(|w| w == b"application/x-secret"));
        assert_eq!(
            record.dependencies,
            vec![[4; 32], [1; 32], [3; 32], [2; 32], [9; 32]]
        );
    }

    #[test]
    fn descriptor_round_trips_filename_and_mime_via_open_with_correct_key_and_aad() {
        let input = make();
        let output = create(input.clone()).expect("create");
        let envelope = codec::decode_signed(&output.events[0].record().canonical_bytes)
            .expect("decode signed");
        let event = codec::decode(&envelope.payload).expect("decode event");
        let aad = codec::descriptor_associated_data(&event, input.signer_endpoint_shared_id);
        let plaintext =
            codec::open_descriptor_slot(&input.key_secret, &event.nonce, &aad, &event.ciphertext)
                .expect("open slot");
        assert_eq!(plaintext.filename, "secret-name.bin");
        assert_eq!(plaintext.mime_type, "application/x-secret");
    }
}

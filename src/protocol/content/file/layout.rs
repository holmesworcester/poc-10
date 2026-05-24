//! Fixed-width layout for content-file facts with a padded sealed-metadata
//! slot.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   message_id (32)
//!   author_user_id (32)
//!   file_id (32)
//!   blob_bytes (u64be)
//!   total_slices (u32be)
//!   slice_bytes (u32be)
//!   root_hash (32)
//!   sealed_metadata (FixedSlot<SEALED_METADATA_BYTES>)

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;
use crate::core::wire::FixedLayout;

use super::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES, SEALED_METADATA_BYTES};

pub const TYPE_CONTENT_FILE: u8 = 54;
pub const FACT_PREFIX_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + 32 + 32 + 32 + 8 + 4 + 4 + FILE_ROOT_HASH_BYTES;
pub const CONTENT_FILE_BYTES: usize =
    FACT_PREFIX_BYTES + wire::FixedSlot::<SEALED_METADATA_BYTES>::LEN + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = CONTENT_FILE_BYTES - ED25519_SIGNATURE_BYTES;

pub fn encode_fact(fact: &ContentFileFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_FILE_BYTES);
    out.u8(TYPE_CONTENT_FILE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.message_id);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.file_id);
    out.u64be(fact.blob_bytes);
    out.u32be(fact.total_slices);
    out.u32be(fact.slice_bytes);
    out.fixed(&fact.root_hash);
    out.fixed_slot_value(&fact.sealed_metadata)
        .map_err(wire_err)?;
    out.fixed(&fact.signature);
    out.finish_exact(CONTENT_FILE_BYTES).map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_len(CONTENT_FILE_BYTES).map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE {
        return Err("expected content file fact".to_string());
    }
    let workspace_id = reader.array().map_err(wire_err)?;
    let created_at_ms = reader.u64be().map_err(wire_err)?;
    let message_id = reader.array().map_err(wire_err)?;
    let author_user_id = reader.array().map_err(wire_err)?;
    let signer_id = reader.array().map_err(wire_err)?;
    let signer_public_key = reader.array().map_err(wire_err)?;
    let file_id = reader.array().map_err(wire_err)?;
    let blob_bytes = reader.u64be().map_err(wire_err)?;
    let total_slices = reader.u32be().map_err(wire_err)?;
    let slice_bytes = reader.u32be().map_err(wire_err)?;
    let root_hash = reader.array().map_err(wire_err)?;
    let sealed_metadata = reader
        .fixed_slot_value::<SEALED_METADATA_BYTES>()
        .map_err(wire_err)?;
    let signature = reader.array().map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    Ok(ContentFileFact {
        workspace_id,
        created_at_ms,
        message_id,
        author_user_id,
        signer_id,
        signer_public_key,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        sealed_metadata,
        signature,
    })
}

pub fn signing_bytes(fact: &ContentFileFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(&encode_fact(fact)?, SIGNATURE_OFFSET..CONTENT_FILE_BYTES)
        .map_err(wire_err)
}

pub fn verify_signature(fact: &ContentFileFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "content file",
    )
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentFileFact {
        ContentFileFact {
            workspace_id: [1; 32],
            created_at_ms: 12345,
            message_id: [2; 32],
            author_user_id: [3; 32],
            signer_id: [9; 32],
            signer_public_key: [10; 32],
            file_id: [4; 32],
            blob_bytes: 1_048_576,
            total_slices: 4,
            slice_bytes: 262_144,
            root_hash: [5; FILE_ROOT_HASH_BYTES],
            sealed_metadata: crate::protocol::content::file::fact::SealedMetadata::new(
                b"sealed-filename-and-mime",
            )
            .expect("metadata"),
            signature: [11; ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn content_file_roundtrips_with_sealed_metadata() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_FILE_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_FILE.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded.pop();
        assert!(decode_fact(&encoded).is_err());
    }
}

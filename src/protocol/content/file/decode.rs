//! Byte decoding for content-file facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! signature checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{CONTENT_FILE_BYTES, TYPE_CONTENT_FILE};
use super::fact::{ContentFileFact, SEALED_METADATA_BYTES};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ContentFileFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
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

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::protocol::content::file::encode::{
        encode_fact, CONTENT_FILE_BYTES, TYPE_CONTENT_FILE,
    };
    use crate::protocol::content::file::fact::FILE_ROOT_HASH_BYTES;

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

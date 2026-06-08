//! Byte decoding for content-file-slice facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{CONTENT_FILE_SLICE_BYTES, TYPE_CONTENT_FILE_SLICE};
use super::fact::{ContentFileSliceFact, FILE_SLICE_BAO_PROOF_BYTES};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ContentFileSliceFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileSliceFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(CONTENT_FILE_SLICE_BYTES)
        .map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE_SLICE {
        return Err("expected content file slice fact".to_string());
    }
    let workspace_id = reader.array().map_err(wire_err)?;
    let created_at_ms = reader.u64be().map_err(wire_err)?;
    let file_id = reader.array().map_err(wire_err)?;
    let slice_index = reader.u32be().map_err(wire_err)?;
    let signer_id = reader.array().map_err(wire_err)?;
    let signer_public_key = reader.array().map_err(wire_err)?;
    let proof = reader
        .fixed_slot_value::<FILE_SLICE_BAO_PROOF_BYTES>()
        .map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    Ok(ContentFileSliceFact {
        workspace_id,
        created_at_ms,
        file_id,
        slice_index,
        signer_id,
        signer_public_key,
        proof,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::content::file_slice::encode::{
        encode_fact, CONTENT_FILE_SLICE_BYTES, TYPE_CONTENT_FILE_SLICE,
    };

    fn on_big_stack<F>(f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn fact() -> ContentFileSliceFact {
        ContentFileSliceFact {
            workspace_id: [1; 32],
            created_at_ms: 4242,
            file_id: [2; 32],
            slice_index: 3,
            signer_id: [9; 32],
            signer_public_key: [10; 32],
            proof: crate::protocol::content::file_slice::fact::FileSliceProof::new(&[0xaa; 128])
                .expect("proof"),
        }
    }

    #[test]
    fn content_file_slice_roundtrips_with_ciphertext() {
        on_big_stack(|| {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), CONTENT_FILE_SLICE_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        });
    }

    #[test]
    fn rejects_wrong_tag() {
        on_big_stack(|| {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_CONTENT_FILE_SLICE.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        });
    }

    #[test]
    fn rejects_wrong_length() {
        on_big_stack(|| {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded.push(0);
            assert!(decode_fact(&encoded).is_err());
        });
    }
}

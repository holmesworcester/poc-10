//! Fixed-width header layout for content-file facts with a length-prefixed
//! opaque sealed-metadata tail.
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
//!   sealed_metadata_len (u32be)
//!   sealed_metadata bytes...

use crate::core::wire;

use super::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES};

pub const TYPE_CONTENT_FILE: u8 = 54;
pub const FACT_PREFIX_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + 32 + 8 + 4 + 4 + FILE_ROOT_HASH_BYTES + 4;

pub fn encode_fact(fact: &ContentFileFact) -> Result<Vec<u8>, String> {
    let sealed_len: u32 = fact
        .sealed_metadata
        .len()
        .try_into()
        .map_err(|_| "content file sealed metadata exceeds u32 length".to_string())?;
    let mut out = wire::Writer::with_capacity(FACT_PREFIX_BYTES + fact.sealed_metadata.len());
    out.u8(TYPE_CONTENT_FILE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.message_id);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.file_id);
    out.u64be(fact.blob_bytes);
    out.u32be(fact.total_slices);
    out.u32be(fact.slice_bytes);
    out.fixed(&fact.root_hash);
    out.u32be(sealed_len);
    out.bytes(&fact.sealed_metadata);
    Ok(out.finish())
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileFact, String> {
    if bytes.len() < FACT_PREFIX_BYTES {
        return Err("content file fact is shorter than its header".to_string());
    }
    let mut reader = wire::Reader::new(bytes);
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE {
        return Err("expected content file fact".to_string());
    }
    let workspace_id = reader.array().map_err(wire_err)?;
    let created_at_ms = reader.u64be().map_err(wire_err)?;
    let message_id = reader.array().map_err(wire_err)?;
    let author_user_id = reader.array().map_err(wire_err)?;
    let file_id = reader.array().map_err(wire_err)?;
    let blob_bytes = reader.u64be().map_err(wire_err)?;
    let total_slices = reader.u32be().map_err(wire_err)?;
    let slice_bytes = reader.u32be().map_err(wire_err)?;
    let root_hash = reader.array().map_err(wire_err)?;
    let sealed_len = reader.u32be().map_err(wire_err)? as usize;
    if bytes.len() != FACT_PREFIX_BYTES + sealed_len {
        return Err("content file fact length does not match declared metadata".to_string());
    }
    let sealed_metadata = reader.bytes(sealed_len).map_err(wire_err)?.to_vec();
    reader.finish().map_err(wire_err)?;
    Ok(ContentFileFact {
        workspace_id,
        created_at_ms,
        message_id,
        author_user_id,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        sealed_metadata,
    })
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
            file_id: [4; 32],
            blob_bytes: 1_048_576,
            total_slices: 4,
            slice_bytes: 262_144,
            root_hash: [5; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"sealed-filename-and-mime".to_vec(),
        }
    }

    #[test]
    fn content_file_roundtrips_with_sealed_metadata() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_PREFIX_BYTES + 24);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_FILE.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_truncated_metadata() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded.pop();
        assert!(decode_fact(&encoded).is_err());
    }
}

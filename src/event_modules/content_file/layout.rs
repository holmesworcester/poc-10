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
pub const HEADER_BYTES: usize = 1 + 32 + 8 + 32 + 32 + 32 + 8 + 4 + 4 + FILE_ROOT_HASH_BYTES + 4;

pub fn encode_fact(fact: &ContentFileFact) -> Result<Vec<u8>, String> {
    let sealed_len: u32 = fact
        .sealed_metadata
        .len()
        .try_into()
        .map_err(|_| "content file sealed metadata exceeds u32 length".to_string())?;
    let mut out = vec![0; HEADER_BYTES + fact.sealed_metadata.len()];
    wire::put_u8(TYPE_CONTENT_FILE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    wire::put_u64be(fact.created_at_ms, &mut out[33..41]).map_err(wire_err)?;
    out[41..73].copy_from_slice(&fact.message_id);
    out[73..105].copy_from_slice(&fact.author_user_id);
    out[105..137].copy_from_slice(&fact.file_id);
    wire::put_u64be(fact.blob_bytes, &mut out[137..145]).map_err(wire_err)?;
    wire::put_u32be(fact.total_slices, &mut out[145..149]).map_err(wire_err)?;
    wire::put_u32be(fact.slice_bytes, &mut out[149..153]).map_err(wire_err)?;
    out[153..185].copy_from_slice(&fact.root_hash);
    wire::put_u32be(sealed_len, &mut out[185..189]).map_err(wire_err)?;
    out[HEADER_BYTES..].copy_from_slice(&fact.sealed_metadata);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileFact, String> {
    if bytes.len() < HEADER_BYTES {
        return Err("content file fact is shorter than its header".to_string());
    }
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE {
        return Err("expected content file fact".to_string());
    }
    let sealed_len = wire::take_u32be(&bytes[185..189]).map_err(wire_err)? as usize;
    if bytes.len() != HEADER_BYTES + sealed_len {
        return Err("content file fact length does not match declared metadata".to_string());
    }
    Ok(ContentFileFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[33..41]).map_err(wire_err)?,
        message_id: bytes[41..73].try_into().unwrap(),
        author_user_id: bytes[73..105].try_into().unwrap(),
        file_id: bytes[105..137].try_into().unwrap(),
        blob_bytes: wire::take_u64be(&bytes[137..145]).map_err(wire_err)?,
        total_slices: wire::take_u32be(&bytes[145..149]).map_err(wire_err)?,
        slice_bytes: wire::take_u32be(&bytes[149..153]).map_err(wire_err)?,
        root_hash: bytes[153..185].try_into().unwrap(),
        sealed_metadata: bytes[HEADER_BYTES..].to_vec(),
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
        assert_eq!(encoded.len(), HEADER_BYTES + 24);
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

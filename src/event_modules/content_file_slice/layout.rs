//! Fixed-width header layout for content-file-slice facts with a length-
//! prefixed opaque ciphertext tail.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   file_id (32)
//!   slice_index (u32be)
//!   ciphertext_len (u32be)
//!   ciphertext bytes...

use crate::core::wire;

use super::fact::ContentFileSliceFact;

pub const TYPE_CONTENT_FILE_SLICE: u8 = 55;
pub const HEADER_BYTES: usize = 1 + 32 + 8 + 32 + 4 + 4;

pub fn encode_fact(fact: &ContentFileSliceFact) -> Result<Vec<u8>, String> {
    let ciphertext_len: u32 = fact
        .ciphertext
        .len()
        .try_into()
        .map_err(|_| "content file slice ciphertext exceeds u32 length".to_string())?;
    let mut out = vec![0; HEADER_BYTES + fact.ciphertext.len()];
    wire::put_u8(TYPE_CONTENT_FILE_SLICE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    wire::put_u64be(fact.created_at_ms, &mut out[33..41]).map_err(wire_err)?;
    out[41..73].copy_from_slice(&fact.file_id);
    wire::put_u32be(fact.slice_index, &mut out[73..77]).map_err(wire_err)?;
    wire::put_u32be(ciphertext_len, &mut out[77..81]).map_err(wire_err)?;
    out[HEADER_BYTES..].copy_from_slice(&fact.ciphertext);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileSliceFact, String> {
    if bytes.len() < HEADER_BYTES {
        return Err("content file slice fact is shorter than its header".to_string());
    }
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE_SLICE {
        return Err("expected content file slice fact".to_string());
    }
    let ciphertext_len = wire::take_u32be(&bytes[77..81]).map_err(wire_err)? as usize;
    if bytes.len() != HEADER_BYTES + ciphertext_len {
        return Err(
            "content file slice fact length does not match declared ciphertext".to_string(),
        );
    }
    Ok(ContentFileSliceFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[33..41]).map_err(wire_err)?,
        file_id: bytes[41..73].try_into().unwrap(),
        slice_index: wire::take_u32be(&bytes[73..77]).map_err(wire_err)?,
        ciphertext: bytes[HEADER_BYTES..].to_vec(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentFileSliceFact {
        ContentFileSliceFact {
            workspace_id: [1; 32],
            created_at_ms: 4242,
            file_id: [2; 32],
            slice_index: 3,
            ciphertext: vec![0xaa; 128],
        }
    }

    #[test]
    fn content_file_slice_roundtrips_with_ciphertext() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), HEADER_BYTES + 128);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_FILE_SLICE.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded.push(0);
        assert!(decode_fact(&encoded).is_err());
    }
}

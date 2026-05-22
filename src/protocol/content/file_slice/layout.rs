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
pub const FACT_PREFIX_BYTES: usize = 1 + 32 + 8 + 32 + 4 + 4;

pub fn encode_fact(fact: &ContentFileSliceFact) -> Result<Vec<u8>, String> {
    let ciphertext_len: u32 = fact
        .ciphertext
        .len()
        .try_into()
        .map_err(|_| "content file slice ciphertext exceeds u32 length".to_string())?;
    let mut out = wire::Writer::with_capacity(FACT_PREFIX_BYTES + fact.ciphertext.len());
    out.u8(TYPE_CONTENT_FILE_SLICE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.file_id);
    out.u32be(fact.slice_index);
    out.u32be(ciphertext_len);
    out.bytes(&fact.ciphertext);
    Ok(out.finish())
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileSliceFact, String> {
    if bytes.len() < FACT_PREFIX_BYTES {
        return Err("content file slice fact is shorter than its header".to_string());
    }
    let mut reader = wire::Reader::new(bytes);
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE_SLICE {
        return Err("expected content file slice fact".to_string());
    }
    let workspace_id = reader.array().map_err(wire_err)?;
    let created_at_ms = reader.u64be().map_err(wire_err)?;
    let file_id = reader.array().map_err(wire_err)?;
    let slice_index = reader.u32be().map_err(wire_err)?;
    let ciphertext_len = reader.u32be().map_err(wire_err)? as usize;
    if bytes.len() != FACT_PREFIX_BYTES + ciphertext_len {
        return Err(
            "content file slice fact length does not match declared ciphertext".to_string(),
        );
    }
    let ciphertext = reader.bytes(ciphertext_len).map_err(wire_err)?.to_vec();
    reader.finish().map_err(wire_err)?;
    Ok(ContentFileSliceFact {
        workspace_id,
        created_at_ms,
        file_id,
        slice_index,
        ciphertext,
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
        assert_eq!(encoded.len(), FACT_PREFIX_BYTES + 128);
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

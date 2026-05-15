//! Fixed-width layout for content-file-deletion target facts.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_file_id (32)
//!   author_user_id (32)

use crate::core::wire;

use super::fact::ContentFileDeletionFact;

pub const TYPE_CONTENT_FILE_DELETION: u8 = 152;

pub const CONTENT_FILE_DELETION_BYTES: usize = 1 + 32 + 8 + 32 + 32;

pub fn encode_fact(fact: &ContentFileDeletionFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; CONTENT_FILE_DELETION_BYTES];
    wire::put_u8(TYPE_CONTENT_FILE_DELETION, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    wire::put_u64be(fact.created_at_ms, &mut out[33..41]).map_err(wire_err)?;
    out[41..73].copy_from_slice(&fact.target_file_id);
    out[73..105].copy_from_slice(&fact.author_user_id);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileDeletionFact, String> {
    wire::expect_len(bytes, CONTENT_FILE_DELETION_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE_DELETION {
        return Err("expected content file deletion fact".to_string());
    }
    Ok(ContentFileDeletionFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[33..41]).map_err(wire_err)?,
        target_file_id: bytes[41..73].try_into().unwrap(),
        author_user_id: bytes[73..105].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentFileDeletionFact {
        ContentFileDeletionFact {
            workspace_id: [1; 32],
            created_at_ms: 9_000,
            target_file_id: [2; 32],
            author_user_id: [3; 32],
        }
    }

    #[test]
    fn content_file_deletion_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_FILE_DELETION_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_FILE_DELETION.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }
}

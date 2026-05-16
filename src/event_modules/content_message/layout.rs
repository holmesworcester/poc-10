//! Fixed-width layout for content-message target facts.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   author_user_id (32)
//!   created_at_ms (u64be)
//!   frontier_id (32)
//!   minute (u64be)
//!   leaf_id (32)
//!   sealed_body_ref (32)

use crate::core::wire;

use super::fact::ContentMessageFact;

pub const TYPE_CONTENT_MESSAGE: u8 = 50;

pub const CONTENT_MESSAGE_BYTES: usize = 1 + 32 + 32 + 8 + 32 + 8 + 32 + 32;

pub fn encode_fact(fact: &ContentMessageFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; CONTENT_MESSAGE_BYTES];
    wire::put_u8(TYPE_CONTENT_MESSAGE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.author_user_id);
    wire::put_u64be(fact.created_at_ms, &mut out[65..73]).map_err(wire_err)?;
    out[73..105].copy_from_slice(&fact.frontier_id);
    wire::put_u64be(fact.minute, &mut out[105..113]).map_err(wire_err)?;
    out[113..145].copy_from_slice(&fact.leaf_id);
    out[145..177].copy_from_slice(&fact.sealed_body_ref);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentMessageFact, String> {
    wire::expect_len(bytes, CONTENT_MESSAGE_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONTENT_MESSAGE {
        return Err("expected content message fact".to_string());
    }
    Ok(ContentMessageFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        author_user_id: bytes[33..65].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
        frontier_id: bytes[73..105].try_into().unwrap(),
        minute: wire::take_u64be(&bytes[105..113]).map_err(wire_err)?,
        leaf_id: bytes[113..145].try_into().unwrap(),
        sealed_body_ref: bytes[145..177].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentMessageFact {
        ContentMessageFact {
            workspace_id: [1; 32],
            author_user_id: [2; 32],
            created_at_ms: 180_000,
            frontier_id: [3; 32],
            minute: 3,
            leaf_id: [4; 32],
            sealed_body_ref: [5; 32],
        }
    }

    #[test]
    fn content_message_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_MESSAGE_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_MESSAGE.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_fact(&[TYPE_CONTENT_MESSAGE; 16]).is_err());
    }
}

//! Fixed-width layout for content-message-deletion target facts.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_message_id (32)
//!   author_user_id (32)

use crate::core::wire;

use super::fact::ContentMessageDeletionFact;

pub const TYPE_CONTENT_MESSAGE_DELETION: u8 = 51;

pub const CONTENT_MESSAGE_DELETION_BYTES: usize = 1 + 32 + 8 + 32 + 32;

pub fn encode_fact(fact: &ContentMessageDeletionFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_MESSAGE_DELETION_BYTES);
    out.u8(TYPE_CONTENT_MESSAGE_DELETION);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.target_message_id);
    out.fixed(&fact.author_user_id);
    out.finish_exact(CONTENT_MESSAGE_DELETION_BYTES)
        .map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentMessageDeletionFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(CONTENT_MESSAGE_DELETION_BYTES)
        .map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_MESSAGE_DELETION {
        return Err("expected content message deletion fact".to_string());
    }
    let fact = ContentMessageDeletionFact {
        workspace_id: reader.array().map_err(wire_err)?,
        created_at_ms: reader.u64be().map_err(wire_err)?,
        target_message_id: reader.array().map_err(wire_err)?,
        author_user_id: reader.array().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentMessageDeletionFact {
        ContentMessageDeletionFact {
            workspace_id: [1; 32],
            created_at_ms: 9_000,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
        }
    }

    #[test]
    fn content_message_deletion_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_MESSAGE_DELETION_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_MESSAGE_DELETION.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }
}

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

use crate::core::schema_dsl::{self, FieldValue};

use super::fact::ContentMessageFact;

pub const TYPE_CONTENT_MESSAGE: u8 = 50;

pub const CONTENT_MESSAGE_BYTES: usize = 1 + 32 + 32 + 8 + 32 + 8 + 32 + 32;

pub fn encode_fact(fact: &ContentMessageFact) -> Result<Vec<u8>, String> {
    schema_dsl::encode_layout_record(
        schema_dsl::facts_layout("content_message_fact"),
        &[
            ("type", FieldValue::U8(TYPE_CONTENT_MESSAGE)),
            (
                "workspace_id",
                FieldValue::Bytes(fact.workspace_id.to_vec()),
            ),
            (
                "author_user_id",
                FieldValue::Bytes(fact.author_user_id.to_vec()),
            ),
            ("created_at_ms", FieldValue::U64(fact.created_at_ms)),
            ("frontier_id", FieldValue::Bytes(fact.frontier_id.to_vec())),
            ("minute", FieldValue::U64(fact.minute)),
            ("leaf_id", FieldValue::Bytes(fact.leaf_id.to_vec())),
            (
                "sealed_message_id",
                FieldValue::Bytes(fact.sealed_body_ref.to_vec()),
            ),
        ],
    )
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentMessageFact, String> {
    let record =
        schema_dsl::decode_layout_record(schema_dsl::facts_layout("content_message_fact"), bytes)
            .map_err(|err| format!("content message fact layout: {err}"))?;
    let tag = record.u8("type")?;
    if tag != TYPE_CONTENT_MESSAGE {
        return Err("expected content message fact".to_string());
    }
    Ok(ContentMessageFact {
        workspace_id: record.bytes_array("workspace_id")?,
        author_user_id: record.bytes_array("author_user_id")?,
        created_at_ms: record.u64("created_at_ms")?,
        frontier_id: record.bytes_array("frontier_id")?,
        minute: record.u64("minute")?,
        leaf_id: record.bytes_array("leaf_id")?,
        sealed_body_ref: record.bytes_array("sealed_message_id")?,
    })
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

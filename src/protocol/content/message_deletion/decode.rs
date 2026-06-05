//! Byte decoding for content-message-deletion target facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! signature checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{CONTENT_MESSAGE_DELETION_BYTES, TYPE_CONTENT_MESSAGE_DELETION};
use super::fact::ContentMessageDeletionFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ContentMessageDeletionFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
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
        target_frontier_id: reader.array().map_err(wire_err)?,
        target_minute: reader.u64be().map_err(wire_err)?,
        author_user_id: reader.array().map_err(wire_err)?,
        signer_id: reader.array().map_err(wire_err)?,
        signer_public_key: reader.array().map_err(wire_err)?,
        signature: reader.array().map_err(wire_err)?,
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
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::protocol::content::message_deletion::encode::{
        encode_fact, CONTENT_MESSAGE_DELETION_BYTES, TYPE_CONTENT_MESSAGE_DELETION,
    };

    fn fact() -> ContentMessageDeletionFact {
        ContentMessageDeletionFact {
            workspace_id: [1; 32],
            created_at_ms: 9_000,
            target_message_id: [2; 32],
            target_frontier_id: [3; 32],
            target_minute: 7,
            author_user_id: [4; 32],
            signer_id: [9; 32],
            signer_public_key: [10; 32],
            signature: [11; ED25519_SIGNATURE_BYTES],
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

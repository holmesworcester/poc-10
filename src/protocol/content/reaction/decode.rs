//! Byte decoding for content-reaction target facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{CONTENT_REACTION_BYTES, TYPE_CONTENT_REACTION};
use super::fact::{ContentReactionFact, REACTION_CIPHERTEXT_BYTES};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ContentReactionFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentReactionFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(CONTENT_REACTION_BYTES)
        .map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_REACTION {
        return Err("expected content reaction fact".to_string());
    }
    let fact = ContentReactionFact {
        workspace_id: reader.array().map_err(wire_err)?,
        created_at_ms: reader.u64be().map_err(wire_err)?,
        target_message_id: reader.array().map_err(wire_err)?,
        author_user_id: reader.array().map_err(wire_err)?,
        signer_id: reader.array().map_err(wire_err)?,
        signer_public_key: reader.array().map_err(wire_err)?,
        nonce: reader.array().map_err(wire_err)?,
        ciphertext: reader
            .fixed_slot_value::<REACTION_CIPHERTEXT_BYTES>()
            .map_err(wire_err)?,
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
    use crate::protocol::content::reaction::encode::{
        encode_fact, CONTENT_REACTION_BYTES, TYPE_CONTENT_REACTION,
    };
    use crate::protocol::content::reaction::fact::REACTION_NONCE_BYTES;

    fn fact() -> ContentReactionFact {
        ContentReactionFact {
            workspace_id: [1; 32],
            created_at_ms: 99_000,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
            signer_id: [9; 32],
            signer_public_key: [10; 32],
            nonce: [4; REACTION_NONCE_BYTES],
            ciphertext: crate::protocol::content::reaction::fact::ReactionCiphertext::new(
                b"sealed-reaction",
            )
            .expect("ciphertext"),
        }
    }

    #[test]
    fn content_reaction_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_REACTION_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_REACTION.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }
}

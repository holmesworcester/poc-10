//! Fixed-width layout for content-reaction target facts.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_message_id (32)
//!   author_user_id (32)
//!   nonce (24)
//!   ciphertext (FixedSlot<REACTION_CIPHERTEXT_BYTES>)

use crate::core::wire;
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{ContentReactionFact, REACTION_CIPHERTEXT_BYTES, REACTION_NONCE_BYTES};

pub const TYPE_CONTENT_REACTION: u8 = 150;

pub const CONTENT_REACTION_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + REACTION_NONCE_BYTES + 4 + REACTION_CIPHERTEXT_BYTES;

pub fn encode_fact(fact: &ContentReactionFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; CONTENT_REACTION_BYTES];
    wire::put_u8(TYPE_CONTENT_REACTION, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    wire::put_u64be(fact.created_at_ms, &mut out[33..41]).map_err(wire_err)?;
    out[41..73].copy_from_slice(&fact.target_message_id);
    out[73..105].copy_from_slice(&fact.author_user_id);
    out[105..129].copy_from_slice(&fact.nonce);
    FixedSlot::<REACTION_CIPHERTEXT_BYTES>::new(&fact.ciphertext)
        .map_err(wire_err)?
        .encode(&mut out[129..])
        .map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentReactionFact, String> {
    wire::expect_len(bytes, CONTENT_REACTION_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONTENT_REACTION {
        return Err("expected content reaction fact".to_string());
    }
    Ok(ContentReactionFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[33..41]).map_err(wire_err)?,
        target_message_id: bytes[41..73].try_into().unwrap(),
        author_user_id: bytes[73..105].try_into().unwrap(),
        nonce: bytes[105..129].try_into().unwrap(),
        ciphertext: FixedSlot::<REACTION_CIPHERTEXT_BYTES>::decode(&bytes[129..])
            .map_err(wire_err)?
            .bytes()
            .to_vec(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentReactionFact {
        ContentReactionFact {
            workspace_id: [1; 32],
            created_at_ms: 99_000,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
            nonce: [4; REACTION_NONCE_BYTES],
            ciphertext: b"sealed-reaction".to_vec(),
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

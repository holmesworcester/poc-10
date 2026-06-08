//! Byte decoding for recipient key facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{RECIPIENT_KEY_BYTES, TYPE_RECIPIENT_KEY};
use super::fact::RecipientKeyFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = RecipientKeyFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_recipient_key(fact.body())
    }
}

pub fn decode_recipient_key(bytes: &[u8]) -> Result<RecipientKeyFact, String> {
    wire::expect_len(bytes, RECIPIENT_KEY_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_RECIPIENT_KEY {
        return Err("expected recipient key".to_string());
    }
    Ok(RecipientKeyFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        endpoint_id: bytes[33..65].try_into().unwrap(),
        recipient_key: bytes[65..97].try_into().unwrap(),
        previous_recipient_key_id: bytes[97..129].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[129..137]).map_err(wire_err)?,
        signer_public_key: bytes[137..169].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::recipient_key::encode::{encode_recipient_key, RECIPIENT_KEY_BYTES};

    fn sample_fact() -> RecipientKeyFact {
        RecipientKeyFact {
            workspace_id: [1; 32],
            endpoint_id: [2; 32],
            recipient_key: [3; 32],
            previous_recipient_key_id: [4; 32],
            created_at_ms: 123,
            signer_public_key: [5; 32],
        }
    }

    #[test]
    fn recipient_key_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded = encode_recipient_key(&fact).expect("encode recipient key");

        assert_eq!(encoded.len(), RECIPIENT_KEY_BYTES);
        assert_eq!(
            decode_recipient_key(&encoded).expect("decode recipient key"),
            fact
        );
    }
}

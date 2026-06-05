//! Byte decoding for key request facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! signature checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{KEY_REQUEST_BYTES, TYPE_KEY_REQUEST};
use super::fact::KeyRequestFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = KeyRequestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_key_request(fact.body())
    }
}

pub fn decode_key_request(bytes: &[u8]) -> Result<KeyRequestFact, String> {
    wire::expect_len(bytes, KEY_REQUEST_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_KEY_REQUEST {
        return Err("expected key request".to_string());
    }
    Ok(KeyRequestFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        requester_endpoint_id: bytes[33..65].try_into().unwrap(),
        responder_endpoint_id: bytes[65..97].try_into().unwrap(),
        frontier_id: bytes[97..129].try_into().unwrap(),
        recipient_key_id: bytes[129..161].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[161..169]).map_err(wire_err)?,
        signer_public_key: bytes[169..201].try_into().unwrap(),
        signature: bytes[201..265].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::protocol::auth::key_request::encode::{encode_key_request, KEY_REQUEST_BYTES};

    fn sample_fact() -> KeyRequestFact {
        KeyRequestFact {
            workspace_id: [1; 32],
            requester_endpoint_id: [2; 32],
            responder_endpoint_id: [3; 32],
            frontier_id: [4; 32],
            recipient_key_id: [5; 32],
            created_at_ms: 123,
            signer_public_key: [6; 32],
            signature: [7; ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn key_request_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded = encode_key_request(&fact).expect("encode key request");

        assert_eq!(encoded.len(), KEY_REQUEST_BYTES);
        assert_eq!(
            decode_key_request(&encoded).expect("decode key request"),
            fact
        );
    }
}

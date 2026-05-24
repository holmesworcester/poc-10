//! Fixed-width layout for key request facts.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;

use super::fact::KeyRequestFact;

pub const TYPE_KEY_REQUEST: u8 = 154;
pub const KEY_REQUEST_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 32 + 8 + 32 + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = KEY_REQUEST_BYTES - ED25519_SIGNATURE_BYTES;

pub fn encode_key_request(fact: &KeyRequestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; KEY_REQUEST_BYTES];
    wire::put_u8(TYPE_KEY_REQUEST, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.requester_endpoint_id);
    out[65..97].copy_from_slice(&fact.responder_endpoint_id);
    out[97..129].copy_from_slice(&fact.frontier_id);
    out[129..161].copy_from_slice(&fact.recipient_key_id);
    wire::put_u64be(fact.created_at_ms, &mut out[161..169]).map_err(wire_err)?;
    out[169..201].copy_from_slice(&fact.signer_public_key);
    out[201..265].copy_from_slice(&fact.signature);
    Ok(out)
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

pub fn signing_bytes(fact: &KeyRequestFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(
        &encode_key_request(fact)?,
        SIGNATURE_OFFSET..KEY_REQUEST_BYTES,
    )
    .map_err(wire_err)
}

pub fn verify_signature(fact: &KeyRequestFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "key request",
    )
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

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

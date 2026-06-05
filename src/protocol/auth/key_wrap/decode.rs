//! Byte decoding for key wrap facts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and the
//! structural coordinate constraints shared with encoding. Id checks live in
//! `authenticate.rs`.

use crate::core::wire;

use super::encode::{validate_key_wrap, KEY_WRAP_BYTES, TYPE_KEY_WRAP};
use super::fact::{KeyWrapFact, WrappedSecretKind};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = KeyWrapFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_key_wrap(fact.body())
    }
}

pub fn decode_key_wrap(bytes: &[u8]) -> Result<KeyWrapFact, String> {
    wire::expect_len(bytes, KEY_WRAP_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_KEY_WRAP {
        return Err("expected key wrap".to_string());
    }
    let fact = KeyWrapFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[33..41]).map_err(wire_err)?,
        signer_endpoint_id: bytes[41..73].try_into().unwrap(),
        frontier_id: bytes[73..105].try_into().unwrap(),
        wrapped_secret_kind: WrappedSecretKind::from_u8(bytes[105])?,
        wrapped_secret_id: bytes[106..138].try_into().unwrap(),
        wrapped_source_secret_id: bytes[138..170].try_into().unwrap(),
        wrapped_tombstone_node_id: bytes[170..202].try_into().unwrap(),
        range_start: wire::take_u64be(&bytes[202..210]).map_err(wire_err)?,
        range_width: wire::take_u64be(&bytes[210..218]).map_err(wire_err)?,
        bit_depth: wire::take_u16be(&bytes[218..220]).map_err(wire_err)?,
        fact_id_prefix: bytes[220..252].try_into().unwrap(),
        recipient_key_id: bytes[252..284].try_into().unwrap(),
        sender_wrap_public_key: bytes[284..316].try_into().unwrap(),
        nonce: bytes[316..340].try_into().unwrap(),
        ciphertext: bytes[340..388].try_into().unwrap(),
    };
    validate_key_wrap(&fact)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::{X25519_PUBLIC_KEY_BYTES, XCHACHA20_POLY1305_NONCE_BYTES};
    use crate::protocol::auth::key_wrap::encode::{encode_key_wrap, KEY_WRAP_BYTES};
    use crate::protocol::auth::key_wrap::fact::KEY_WRAP_CIPHERTEXT_BYTES;

    fn sample_fact() -> KeyWrapFact {
        KeyWrapFact {
            workspace_id: [1; 32],
            created_at_ms: 123,
            signer_endpoint_id: [2; 32],
            frontier_id: [3; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: [4; 32],
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            recipient_key_id: [5; 32],
            sender_wrap_public_key: [6; X25519_PUBLIC_KEY_BYTES],
            nonce: [7; XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [8; KEY_WRAP_CIPHERTEXT_BYTES],
        }
    }

    #[test]
    fn key_wrap_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded = encode_key_wrap(&fact).expect("encode key wrap");

        assert_eq!(encoded.len(), KEY_WRAP_BYTES);
        assert_eq!(decode_key_wrap(&encoded).expect("decode key wrap"), fact);
    }
}

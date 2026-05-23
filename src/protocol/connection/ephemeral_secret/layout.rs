//! Stable bytes for local connection ephemeral-secret facts.
//!
//! The layout is fixed width: `tag(1) || owner_endpoint(32) ||
//! ephemeral_private_key(32) || ephemeral_public_key(32) ||
//! created_at_ms(8)`. Encoding and decoding preserve byte shape only; they do
//! not decide whether the keypair is valid or whether the local fact should be
//! admitted.
//!
//! Change this file only for wire compatibility of the secret fact. Keypair
//! validation belongs in `project.rs`, and durable row shape belongs in
//! `rows.rs`.

use crate::core::crypto::{X25519_PRIVATE_KEY_BYTES, X25519_PUBLIC_KEY_BYTES};
use crate::core::wire;

use super::fact::ConnectionEphemeralSecretFact;

pub const TYPE_CONNECTION_EPHEMERAL_SECRET: u8 = 43;

pub const FACT_BYTES: usize = 1 + 32 + X25519_PRIVATE_KEY_BYTES + X25519_PUBLIC_KEY_BYTES + 8;

pub fn encode_fact(fact: &ConnectionEphemeralSecretFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_EPHEMERAL_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.owner_endpoint);
    out[33..65].copy_from_slice(&fact.ephemeral_private_key);
    out[65..97].copy_from_slice(&fact.ephemeral_public_key);
    wire::put_u64be(fact.created_at_ms, &mut out[97..105]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionEphemeralSecretFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_EPHEMERAL_SECRET {
        return Err("expected connection ephemeral secret fact".to_string());
    }
    let mut owner_endpoint = [0; 32];
    owner_endpoint.copy_from_slice(&bytes[1..33]);
    let mut ephemeral_private_key = [0; X25519_PRIVATE_KEY_BYTES];
    ephemeral_private_key.copy_from_slice(&bytes[33..65]);
    let mut ephemeral_public_key = [0; X25519_PUBLIC_KEY_BYTES];
    ephemeral_public_key.copy_from_slice(&bytes[65..97]);
    let created_at_ms = wire::take_u64be(&bytes[97..105]).map_err(wire_err)?;
    Ok(ConnectionEphemeralSecretFact {
        owner_endpoint,
        ephemeral_private_key,
        ephemeral_public_key,
        created_at_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ConnectionEphemeralSecretFact {
        ConnectionEphemeralSecretFact {
            owner_endpoint: [1; 32],
            ephemeral_private_key: [2; X25519_PRIVATE_KEY_BYTES],
            ephemeral_public_key: [3; X25519_PUBLIC_KEY_BYTES],
            created_at_ms: 4,
        }
    }

    #[test]
    fn roundtrip_fixed_width() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag_or_length() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_CONNECTION_EPHEMERAL_SECRET.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }
}

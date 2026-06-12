//! Byte decoding for local key secret facts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and that the
//! decoded material is canonical. Id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{encode_local_key_secret, LOCAL_KEY_SECRET_BYTES, TYPE_LOCAL_KEY_SECRET};
use super::fact::LocalKeySecretFact;

pub fn decode_local_key_secret(bytes: &[u8]) -> Result<LocalKeySecretFact, String> {
    wire::expect_len(bytes, LOCAL_KEY_SECRET_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_LOCAL_KEY_SECRET {
        return Err("expected local key secret".to_string());
    }
    let fact = LocalKeySecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        frontier_id: bytes[33..65].try_into().unwrap(),
        owner_endpoint_id: bytes[65..97].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[97..105]).map_err(wire_err)?,
        key_secret: bytes[105..137].try_into().unwrap(),
    };
    encode_local_key_secret(&fact)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::local_key_secret::encode::{
        encode_local_key_secret, LOCAL_KEY_SECRET_BYTES,
    };

    fn sample_fact() -> LocalKeySecretFact {
        LocalKeySecretFact {
            workspace_id: [1; 32],
            frontier_id: [2; 32],
            owner_endpoint_id: [3; 32],
            created_at_ms: 123,
            key_secret: [4; 32],
        }
    }

    #[test]
    fn local_key_secret_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded = encode_local_key_secret(&fact).expect("encode local key secret");

        assert_eq!(encoded.len(), LOCAL_KEY_SECRET_BYTES);
        assert_eq!(
            decode_local_key_secret(&encoded).expect("decode local key secret"),
            fact
        );
    }
}

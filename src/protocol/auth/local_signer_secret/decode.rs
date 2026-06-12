//! Byte decoding for local signer-secret facts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and that the
//! decoded material is canonical. Id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{validate, LOCAL_SIGNER_SECRET_BYTES, TYPE_LOCAL_SIGNER_SECRET};
use super::fact::LocalSignerSecretFact;

pub fn decode_fact(bytes: &[u8]) -> Result<LocalSignerSecretFact, String> {
    wire::expect_len(bytes, LOCAL_SIGNER_SECRET_BYTES).map_err(wire_err)?;
    let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if actual != TYPE_LOCAL_SIGNER_SECRET {
        return Err("expected local signer secret".to_string());
    }
    let fact = LocalSignerSecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        signer_id: bytes[33..65].try_into().unwrap(),
        public_key: bytes[65..97].try_into().unwrap(),
        private_key: bytes[97..129].try_into().unwrap(),
    };
    validate(&fact)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::protocol::auth::local_signer_secret::encode::{
        encode_fact, LOCAL_SIGNER_SECRET_BYTES,
    };

    fn sample_fact() -> LocalSignerSecretFact {
        let private_key = [9; 32];
        let public_key = crypto::ed25519_public_key(&private_key);
        LocalSignerSecretFact {
            workspace_id: [1; 32],
            signer_id: [2; 32],
            public_key,
            private_key,
        }
    }

    #[test]
    fn local_signer_secret_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded = encode_fact(&fact).expect("encode local signer secret");

        assert_eq!(encoded.len(), LOCAL_SIGNER_SECRET_BYTES);
        assert_eq!(
            decode_fact(&encoded).expect("decode local signer secret"),
            fact
        );
    }
}

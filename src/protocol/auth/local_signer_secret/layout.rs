//! Fixed layout for local signer-secret facts.
//!
//! The layout is local-only private key material:
//! `type || workspace_id || signer_id || public_key || private_key`. Encoding
//! validates that the private key derives the stored public key. Do not add
//! signed-envelope parsing here; this family only owns local signing material.

use crate::core::crypto;
use crate::core::wire;

use super::fact::LocalSignerSecretFact;

pub const TYPE_LOCAL_SIGNER_SECRET: u8 = 133;
pub const LOCAL_SIGNER_SECRET_BYTES: usize = 1 + 32 + 32 + 32 + 32;

pub fn encode_fact(fact: &LocalSignerSecretFact) -> Result<Vec<u8>, String> {
    validate(fact)?;
    let mut out = vec![0; LOCAL_SIGNER_SECRET_BYTES];
    wire::put_u8(TYPE_LOCAL_SIGNER_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.signer_id);
    out[65..97].copy_from_slice(&fact.public_key);
    out[97..129].copy_from_slice(&fact.private_key);
    Ok(out)
}

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

fn validate(fact: &LocalSignerSecretFact) -> Result<(), String> {
    if fact.workspace_id.iter().all(|byte| *byte == 0) {
        return Err("local signer secret workspace_id cannot be empty".to_string());
    }
    if fact.signer_id.iter().all(|byte| *byte == 0) {
        return Err("local signer secret signer_id cannot be empty".to_string());
    }
    if fact.private_key.iter().all(|byte| *byte == 0) {
        return Err("local signer secret private_key cannot be empty".to_string());
    }
    if crypto::ed25519_public_key(&fact.private_key) != fact.public_key {
        return Err("local signer secret public_key does not match private_key".to_string());
    }
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

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

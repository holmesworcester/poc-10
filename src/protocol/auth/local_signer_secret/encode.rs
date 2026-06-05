//! Canonical byte encoding for local signer-secret facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, and the field validation that canonical material must satisfy. It
//! does not authenticate, inspect context, or materialize rows.
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

pub(crate) fn validate(fact: &LocalSignerSecretFact) -> Result<(), String> {
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

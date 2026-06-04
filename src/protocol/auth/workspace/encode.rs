//! Canonical byte encoding for workspace facts.
//!
//! This file owns byte construction only: fixed field order, field widths, the
//! fact tag, fact payload bytes, and the pure signing transcript. It does not
//! sign, authenticate, inspect context, or materialize rows.

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::{WorkspaceFact, WORKSPACE_NAME_BYTES};

pub const TYPE_WORKSPACE: u8 = 131;
pub const FACT_BYTES: usize = 1 + PAYLOAD_BYTES;
pub const PAYLOAD_BYTES: usize = 8 + 32 + WORKSPACE_NAME_BYTES + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = FACT_BYTES - ED25519_SIGNATURE_BYTES;

pub fn encode_fact(fact: &WorkspaceFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_WORKSPACE, &mut out[0..1]).map_err(wire_err)?;
    encode_payload_fields(fact, &mut out[1..])?;
    Ok(out)
}

#[cfg(test)]
pub(crate) fn encode_payload(fact: &WorkspaceFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; PAYLOAD_BYTES];
    encode_payload_fields(fact, &mut out)?;
    Ok(out)
}

fn encode_payload_fields(fact: &WorkspaceFact, out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, PAYLOAD_BYTES).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[0..8]).map_err(wire_err)?;
    out[8..40].copy_from_slice(&fact.public_key);
    out[40..40 + WORKSPACE_NAME_BYTES].copy_from_slice(fact.name.padded_bytes());
    out[40 + WORKSPACE_NAME_BYTES..].copy_from_slice(&fact.signature);
    Ok(())
}

pub fn signing_bytes(fact: &WorkspaceFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(&encode_fact(fact)?, SIGNATURE_OFFSET..FACT_BYTES)
        .map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

//! Canonical byte encoding for user facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, the projection row value bytes. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! User names are stored in a fixed slot so fact ids are stable and row values
//! can be decoded without schema-dependent parsing. Encoding rejects embedded
//! NUL bytes; keep those byte invariants here.

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::{UserFact, Username, USERNAME_BYTES};

pub const TYPE_USER: u8 = 14;
pub const FACT_BYTES: usize = 1 + 8 + 32 + 32 + USERNAME_BYTES + 32 + 32 + ED25519_SIGNATURE_BYTES;
pub fn encode_fact(fact: &UserFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_USER, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    out[41..73].copy_from_slice(&fact.public_key);
    write_username(&fact.username, &mut out[73..73 + USERNAME_BYTES])?;
    let signer_start = 73 + USERNAME_BYTES;
    out[signer_start..signer_start + 32].copy_from_slice(&fact.signer_id);
    out[signer_start + 32..signer_start + 64].copy_from_slice(&fact.signer_public_key);
    out[signer_start + 64..signer_start + 64 + ED25519_SIGNATURE_BYTES]
        .copy_from_slice(&fact.signature);
    Ok(out)
}

fn write_username(username: &Username, out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, USERNAME_BYTES).map_err(wire_err)?;
    out.copy_from_slice(username.padded_bytes());
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

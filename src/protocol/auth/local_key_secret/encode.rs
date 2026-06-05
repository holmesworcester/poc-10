//! Canonical byte encoding for local key secret facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, and the field validation that canonical material must satisfy. It
//! does not authenticate, inspect context, or materialize rows.

use crate::core::wire;

use super::fact::LocalKeySecretFact;

pub const TYPE_LOCAL_KEY_SECRET: u8 = 152;
pub const LOCAL_KEY_SECRET_BYTES: usize = 1 + 32 + 32 + 32 + 8 + 32;

pub fn encode_local_key_secret(fact: &LocalKeySecretFact) -> Result<Vec<u8>, String> {
    if fact.key_secret.iter().all(|byte| *byte == 0) {
        return Err("local key secret material cannot be empty".to_string());
    }
    let mut out = vec![0; LOCAL_KEY_SECRET_BYTES];
    wire::put_u8(TYPE_LOCAL_KEY_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.frontier_id);
    out[65..97].copy_from_slice(&fact.owner_endpoint_id);
    wire::put_u64be(fact.created_at_ms, &mut out[97..105]).map_err(wire_err)?;
    out[105..137].copy_from_slice(&fact.key_secret);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

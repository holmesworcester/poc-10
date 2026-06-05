//! Canonical byte encoding for local endpoint facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. It does not authenticate, inspect context, or materialize rows.

use crate::core::wire;

use super::fact::EndpointFact;

pub const TYPE_LOCAL_ENDPOINT: u8 = 128;
pub const FACT_BYTES: usize = 1 + 32 + 32 + 32 + 32;

pub fn encode_fact(fact: &EndpointFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_LOCAL_ENDPOINT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.endpoint);
    out[33..65].copy_from_slice(&fact.secret);
    out[65..97].copy_from_slice(&fact.signing_public_key);
    out[97..129].copy_from_slice(&fact.signing_secret);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

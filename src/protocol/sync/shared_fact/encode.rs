//! Canonical byte encoding for sync shared-fact declarations.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. A shared-fact declaration is just a workspace id and fact id; the
//! actual fact bytes stay in the core fact store.

use crate::core::wire;

use super::fact::SharedFact;

pub const TYPE_SHARED_FACT: u8 = 162;
pub const ENCODED_BYTES: usize = 1 + 32 + 32;

pub fn encode_fact(fact: &SharedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SHARED_FACT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.fact_id);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

//! Canonical byte encoding for the sync have-id fact.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. Tag + connection id (32) + timestamp (u64) + advertised fact id (32).

use crate::core::wire;

use super::fact::SyncHaveIdFact;

pub const TYPE_SYNC_HAVE_ID: u8 = 166;
pub const ENCODED_BYTES: usize = 1 + 32 + 8 + 32;

pub fn encode_fact(fact: &SyncHaveIdFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SYNC_HAVE_ID, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    wire::put_u64be(fact.timestamp, &mut out[33..41]).map_err(wire_err)?;
    out[41..73].copy_from_slice(&fact.fact_id);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

//! Canonical byte encoding for the sync need-id fact.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. Tag + connection id (32) + requested fact id (32).

use crate::core::wire;

use super::fact::SyncNeedIdFact;

pub const TYPE_SYNC_NEED_ID: u8 = 167;
pub const ENCODED_BYTES: usize = 1 + 32 + 32;

pub fn encode_fact(fact: &SyncNeedIdFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SYNC_NEED_ID, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    out[33..65].copy_from_slice(&fact.fact_id);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

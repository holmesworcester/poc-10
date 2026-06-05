//! Canonical byte encoding for the sync compare fact.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. Tag + connection id + range (u64,u64) + summary count (u64) +
//! fingerprint (32 bytes) + response flag (u8). An inverted range is rejected so
//! it cannot be encoded.

use crate::core::wire;

use super::fact::SyncCompareFact;

pub const TYPE_SYNC_COMPARE: u8 = 165;
pub const ENCODED_BYTES: usize = 1 + 32 + 8 + 8 + 8 + 32 + 1;

pub fn encode_fact(fact: &SyncCompareFact) -> Result<Vec<u8>, String> {
    if fact.range.start > fact.range.end {
        return Err("sync compare range is inverted".to_string());
    }
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SYNC_COMPARE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    wire::put_u64be(fact.range.start, &mut out[33..41]).map_err(wire_err)?;
    wire::put_u64be(fact.range.end, &mut out[41..49]).map_err(wire_err)?;
    wire::put_u64be(fact.summary.count, &mut out[49..57]).map_err(wire_err)?;
    out[57..89].copy_from_slice(&fact.summary.fingerprint);
    wire::put_u8(u8::from(fact.response_requested), &mut out[89..90]).map_err(wire_err)?;
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

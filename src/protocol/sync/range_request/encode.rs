//! Canonical byte encoding for sync range requests.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. Encoding rejects inverted ranges so downstream sync planners can
//! assume `start <= end`. It does not decide whether the peer may receive the
//! range.

use crate::core::wire;

use super::fact::SyncRangeRequestFact;

pub const TYPE_SYNC_RANGE_REQUEST: u8 = 160;
pub const ENCODED_BYTES: usize = 1 + 32 + 32 + 8 + 8;

pub fn encode_fact(fact: &SyncRangeRequestFact) -> Result<Vec<u8>, String> {
    if fact.start > fact.end {
        return Err("sync range request is inverted".to_string());
    }
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SYNC_RANGE_REQUEST, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.connection_id);
    wire::put_u64be(fact.start, &mut out[65..73]).map_err(wire_err)?;
    wire::put_u64be(fact.end, &mut out[73..81]).map_err(wire_err)?;
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

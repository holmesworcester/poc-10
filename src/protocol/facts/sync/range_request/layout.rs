//! Fixed-width layout for sync range requests.
//!
//! Range requests carry an inclusive timestamp interval for a workspace on one
//! connection. Encoding and decoding reject inverted ranges so downstream sync
//! planners can assume `start <= end`. This module does not decide whether the
//! peer may receive the range.

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

pub fn decode_fact(bytes: &[u8]) -> Result<SyncRangeRequestFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_SYNC_RANGE_REQUEST {
        return Err("expected sync range request".to_string());
    }
    let fact = SyncRangeRequestFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        connection_id: bytes[33..65].try_into().unwrap(),
        start: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
        end: wire::take_u64be(&bytes[73..81]).map_err(wire_err)?,
    };
    encode_fact(&fact)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

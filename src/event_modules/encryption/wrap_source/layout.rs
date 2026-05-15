//! Fixed-width layout for removal-frontier facts (wrap-source roots).

use super::fact::RemovalFrontierFact;
use crate::core::wire;

pub const TYPE_REMOVAL_FRONTIER: u8 = 151;
pub const REMOVAL_FRONTIER_BYTES: usize = 1 + 32 + 32 + 8;

pub fn encode_removal_frontier(fact: &RemovalFrontierFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; REMOVAL_FRONTIER_BYTES];
    wire::put_u8(TYPE_REMOVAL_FRONTIER, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.owner_endpoint_id);
    wire::put_u64be(fact.created_at_ms, &mut out[65..73]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_removal_frontier(bytes: &[u8]) -> Result<RemovalFrontierFact, String> {
    wire::expect_len(bytes, REMOVAL_FRONTIER_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_REMOVAL_FRONTIER, "removal frontier")?;
    Ok(RemovalFrontierFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        owner_endpoint_id: bytes[33..65].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
    })
}

fn expect_tag(bytes: &[u8], expected: u8, label: &str) -> Result<(), String> {
    let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {label}"))
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

//! Canonical byte encoding for removal frontier facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. It does not sign, authenticate, inspect context, or materialize rows.

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::RemovalFrontierFact;

pub const TYPE_REMOVAL_FRONTIER: u8 = 151;
pub const REMOVAL_FRONTIER_BYTES: usize = 1 + 32 + 32 + 8 + 32 + ED25519_SIGNATURE_BYTES;
pub fn encode_removal_frontier(fact: &RemovalFrontierFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; REMOVAL_FRONTIER_BYTES];
    wire::put_u8(TYPE_REMOVAL_FRONTIER, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.owner_endpoint_id);
    wire::put_u64be(fact.created_at_ms, &mut out[65..73]).map_err(wire_err)?;
    out[73..105].copy_from_slice(&fact.signer_public_key);
    out[105..169].copy_from_slice(&fact.signature);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

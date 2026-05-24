//! Fixed-width layout for removal frontier facts.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;

use super::fact::RemovalFrontierFact;

pub const TYPE_REMOVAL_FRONTIER: u8 = 151;
pub const REMOVAL_FRONTIER_BYTES: usize = 1 + 32 + 32 + 8 + 32 + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = REMOVAL_FRONTIER_BYTES - ED25519_SIGNATURE_BYTES;

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

pub fn decode_removal_frontier(bytes: &[u8]) -> Result<RemovalFrontierFact, String> {
    wire::expect_len(bytes, REMOVAL_FRONTIER_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_REMOVAL_FRONTIER {
        return Err("expected removal frontier".to_string());
    }
    Ok(RemovalFrontierFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        owner_endpoint_id: bytes[33..65].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
        signer_public_key: bytes[73..105].try_into().unwrap(),
        signature: bytes[105..169].try_into().unwrap(),
    })
}

pub fn signing_bytes(fact: &RemovalFrontierFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(
        &encode_removal_frontier(fact)?,
        SIGNATURE_OFFSET..REMOVAL_FRONTIER_BYTES,
    )
    .map_err(wire_err)
}

pub fn verify_signature(fact: &RemovalFrontierFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "removal frontier",
    )
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

//! Canonical byte encoding for device-invite facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, the projection row value bytes. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! Layout: `type(1) || created_at_ms(8) || workspace_id(32) ||
//! user_authority_fact_id(32) || user_invite_fact_id_or_zero(32) ||
//! public_key(32)`.

use crate::core::wire;

use super::fact::DeviceInviteFact;

pub const TYPE_DEVICE_INVITE: u8 = 134;
/// Layout: `type(1) || created_at_ms(8) || workspace_id(32) ||
/// user_authority_fact_id(32) || user_invite_fact_id_or_zero(32) ||
/// public_key(32)`.
pub const FACT_BYTES: usize = 1 + 8 + 32 + 32 + 32 + 32 + 32 + 32;
pub fn encode_fact(fact: &DeviceInviteFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_DEVICE_INVITE, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    out[41..73].copy_from_slice(&fact.user_authority_fact_id);
    out[73..105].copy_from_slice(&fact.user_invite_fact_id.unwrap_or([0; 32]));
    out[105..137].copy_from_slice(&fact.public_key);
    out[137..169].copy_from_slice(&fact.signer_id);
    out[169..201].copy_from_slice(&fact.signer_public_key);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

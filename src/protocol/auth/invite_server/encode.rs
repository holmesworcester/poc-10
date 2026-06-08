//! Canonical byte encoding for invite-server facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. Invite-server facts advertise server-side invite material under
//! workspace authority. It does not sign, authenticate, inspect context, or
//! materialize rows.
//!
//! Wire format:
//!
//! ```text
//! type(1) || created_at_ms(8) || public_key(32) || workspace_id(32) ||
//!     authority_fact_id(32) || signer_id(32) || signer_public_key(32)
//! ```

use crate::core::wire;

use super::fact::InviteServerFact;

pub const TYPE_INVITE_SERVER: u8 = 136;
/// Layout: `type(1) || created_at_ms(8) || public_key(32) || workspace_id(32) ||
/// authority_fact_id(32)`.
pub const FACT_BYTES: usize = 1 + 8 + 32 + 32 + 32 + 32 + 32;
pub fn encode_fact(fact: &InviteServerFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_INVITE_SERVER, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.public_key);
    out[41..73].copy_from_slice(&fact.workspace_id);
    out[73..105].copy_from_slice(&fact.authority_fact_id);
    out[105..137].copy_from_slice(&fact.signer_id);
    out[137..169].copy_from_slice(&fact.signer_public_key);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

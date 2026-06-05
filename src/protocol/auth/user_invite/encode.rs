//! Canonical byte encoding for user-invite facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, the projection row value bytes. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! User invites name the invited public key, workspace, and authority fact. The
//! row value mirrors the fact fields projection needs later when a user or
//! endpoint claims the invite.

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::UserInviteFact;

pub const TYPE_USER_INVITE: u8 = 10;
/// Layout: `type(1) || created_at_ms(8) || public_key(32) || workspace_id(32) ||
/// authority_fact_id(32)`.
pub const FACT_BYTES: usize = 1 + 8 + 32 + 32 + 32 + 32 + 32 + ED25519_SIGNATURE_BYTES;
pub fn encode_fact(fact: &UserInviteFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_USER_INVITE, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.public_key);
    out[41..73].copy_from_slice(&fact.workspace_id);
    out[73..105].copy_from_slice(&fact.authority_fact_id);
    out[105..137].copy_from_slice(&fact.signer_id);
    out[137..169].copy_from_slice(&fact.signer_public_key);
    out[169..233].copy_from_slice(&fact.signature);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

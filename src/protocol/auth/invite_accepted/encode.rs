//! Canonical byte encoding for invite-accepted facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. Invite acceptance joins an invite, a locally held bootstrap secret,
//! and the endpoint that will enter the workspace; the bytes store only stable
//! ids and the bootstrap hash, never the private bootstrap secret. It does not
//! authenticate, inspect context, or materialize rows.
//!
//! Wire format:
//!
//! ```text
//! type(1) || workspace_id(32) || invite_fact_id(32) ||
//!     invite_secret_fact_id(32) || bootstrap_hash(32) || accepted_endpoint_id(32)
//! ```

use crate::core::wire;

use super::fact::InviteAcceptedFact;

pub const TYPE_INVITE_ACCEPTED: u8 = 146;
/// Layout: `type(1) || workspace_id(32) || invite_fact_id(32) ||
/// invite_secret_fact_id(32) || bootstrap_hash(32) || accepted_endpoint_id(32)`.
pub const FACT_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 32;

pub fn encode_fact(fact: &InviteAcceptedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_INVITE_ACCEPTED, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.invite_fact_id);
    out[65..97].copy_from_slice(&fact.invite_secret_fact_id);
    out[97..129].copy_from_slice(&fact.bootstrap_hash);
    out[129..161].copy_from_slice(&fact.accepted_endpoint_id);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

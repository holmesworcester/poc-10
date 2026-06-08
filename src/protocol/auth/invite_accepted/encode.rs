//! Canonical byte encoding for invite-accepted facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. Invite acceptance joins an invite link, the bootstrap secret carried
//! by that link, and the endpoint that accepted it. It does not authenticate,
//! inspect context, or materialize rows.
//!
//! Wire format:
//!
//! ```text
//! type(1) || workspace_id(32) || invite_fact_id(32) || bootstrap_hash(32) ||
//!     bootstrap_secret(32) || accepted_endpoint_id(32) ||
//!     bootstrap_endpoint_id(32) || bootstrap_addr(19) ||
//!     user_authority_fact_id_or_zero(32) || endpoint_role(1) || identity_scope(1)
//! ```

use crate::core::wire;
use crate::protocol::connection::request::encode::{encode_optional_addr, ADDR_BLOCK_BYTES};

use super::fact::InviteAcceptedFact;

pub const TYPE_INVITE_ACCEPTED: u8 = 146;
pub const FACT_BYTES: usize = 1 + (32 * 7) + ADDR_BLOCK_BYTES + 1 + 1;

pub fn encode_fact(fact: &InviteAcceptedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_INVITE_ACCEPTED, &mut out[0..1]).map_err(wire_err)?;
    let mut cursor = 1;
    out[cursor..cursor + 32].copy_from_slice(&fact.workspace_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.invite_fact_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.bootstrap_hash);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.bootstrap_secret);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.accepted_endpoint_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.bootstrap_endpoint_id);
    cursor += 32;
    out[cursor..cursor + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(Some(fact.bootstrap_addr))?);
    cursor += ADDR_BLOCK_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.user_authority_fact_id.unwrap_or([0; 32]));
    cursor += 32;
    wire::put_u8(fact.endpoint_role.as_u8(), &mut out[cursor..cursor + 1]).map_err(wire_err)?;
    cursor += 1;
    wire::put_u8(u8::from(fact.identity_scope), &mut out[cursor..cursor + 1]).map_err(wire_err)?;
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

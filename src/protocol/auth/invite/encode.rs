//! Canonical byte encoding for invite-secret facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. Invite secrets are local bootstrap capabilities; their durable bytes
//! store only the bootstrap hash, secret material, and optional scoped
//! workspace and invite ids. It does not authenticate, inspect context, or
//! materialize rows.
//!
//! Wire format:
//!
//! ```text
//! type(1) || bootstrap_hash(32) || bootstrap_secret(32) ||
//!     workspace_id_or_zero(32) || invite_fact_id_or_zero(32)
//! ```

use crate::core::wire;

use super::fact::InviteSecretFact;

pub const TYPE_INVITE_SECRET: u8 = 129;
/// Layout: `type(1) || bootstrap_hash(32) || bootstrap_secret(32) ||
/// workspace_id_or_zero(32) || invite_fact_id_or_zero(32)`.
pub const FACT_BYTES: usize = 1 + 32 + 32 + 32 + 32;

pub fn encode_fact(fact: &InviteSecretFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_INVITE_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.bootstrap_hash);
    out[33..65].copy_from_slice(&fact.bootstrap_secret);
    out[65..97].copy_from_slice(&fact.workspace_id.unwrap_or([0; 32]));
    out[97..129].copy_from_slice(&fact.invite_fact_id.unwrap_or([0; 32]));
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

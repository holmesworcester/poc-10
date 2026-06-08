//! Canonical byte encoding for retention policy facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, the `None`-supersedes sentinel. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! Body shape:
//!
//! ```text
//! tag(1) || created_at_ms(8) || workspace_id(32) || scope_kind(1)
//!        || scope_id(32) || author_user_id(32) || signer_id(32)
//!        || signer_public_key(32) || ttl_minutes(4) || retire_minute(8)
//!        || supersedes_policy_id(32)
//! ```
//!
//! `supersedes_policy_id` uses an all-zero sentinel to encode the
//! `None` variant (first policy in the scope's chain).

use crate::core::wire;

use super::fact::RetentionPolicyFact;

pub const TYPE_RETENTION_POLICY: u8 = 147;

pub const FACT_BYTES: usize = 1 + 8 + 32 + 1 + 32 + 32 + 32 + 32 + 4 + 8 + 32;
pub const NO_PREVIOUS_POLICY_ID: [u8; 32] = [0; 32];

pub fn encode_fact(fact: &RetentionPolicyFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_RETENTION_POLICY, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    wire::put_u8(fact.scope_kind, &mut out[41..42]).map_err(wire_err)?;
    out[42..74].copy_from_slice(&fact.scope_id);
    out[74..106].copy_from_slice(&fact.author_user_id);
    out[106..138].copy_from_slice(&fact.signer_id);
    out[138..170].copy_from_slice(&fact.signer_public_key);
    wire::put_u32be(fact.ttl_minutes, &mut out[170..174]).map_err(wire_err)?;
    wire::put_u64be(fact.retire_minute, &mut out[174..182]).map_err(wire_err)?;
    let supersedes = fact.supersedes_policy_id.unwrap_or(NO_PREVIOUS_POLICY_ID);
    out[182..214].copy_from_slice(&supersedes);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

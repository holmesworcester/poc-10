//! Canonical byte encoding for local secret-retirement facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, and the field validation that gates a canonical encoding. It does
//! not authenticate, inspect context, or materialize rows.

use crate::core::wire;

use super::fact::{LocalSecretRetirementFact, RETIRE_REASON_CHOP};

pub const TYPE_LOCAL_SECRET_RETIREMENT: u8 = 157;
pub const LOCAL_SECRET_RETIREMENT_BYTES: usize = 1 + 32 + 32 + 1 + 8 + 8;

pub fn encode_fact(fact: &LocalSecretRetirementFact) -> Result<Vec<u8>, String> {
    validate_fact(fact)?;
    let mut out = vec![0; LOCAL_SECRET_RETIREMENT_BYTES];
    wire::put_u8(TYPE_LOCAL_SECRET_RETIREMENT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.target_secret_id);
    wire::put_u8(fact.reason_kind, &mut out[65..66]).map_err(wire_err)?;
    wire::put_u64be(fact.floor_minute, &mut out[66..74]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[74..82]).map_err(wire_err)?;
    Ok(out)
}

pub(crate) fn validate_fact(fact: &LocalSecretRetirementFact) -> Result<(), String> {
    if fact.workspace_id.iter().all(|byte| *byte == 0) {
        return Err("local secret retirement workspace_id cannot be empty".to_string());
    }
    if fact.target_secret_id.iter().all(|byte| *byte == 0) {
        return Err("local secret retirement target_secret_id cannot be empty".to_string());
    }
    if fact.reason_kind != RETIRE_REASON_CHOP {
        return Err("local secret retirement reason is unsupported".to_string());
    }
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

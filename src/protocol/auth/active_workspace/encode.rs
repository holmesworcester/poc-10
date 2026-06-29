//! Canonical byte encoding for active-workspace facts.
//!
//! This file owns byte construction only: the fact tag and the fixed-width
//! payload. It does not authenticate, inspect context, or materialize rows.

use super::fact::ActiveWorkspaceFact;

pub const TYPE_ACTIVE_WORKSPACE: u8 = 56;
pub const FACT_BYTES: usize = 1 + 8 + 32;

pub fn encode_fact(fact: &ActiveWorkspaceFact) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(FACT_BYTES);
    out.push(TYPE_ACTIVE_WORKSPACE);
    out.extend_from_slice(&fact.effective_at_ms.to_be_bytes());
    out.extend_from_slice(&fact.workspace_id);
    Ok(out)
}

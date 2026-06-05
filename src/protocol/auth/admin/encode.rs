//! Canonical byte encoding for admin-grant facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, and the projection row value bytes. It does not sign, authenticate,
//! inspect context, or materialize rows.
//!
//! Wire format:
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32) || public_key(32)
//!         || authority_fact_id(32) || user_fact_id(32) || signer_id(32)
//!         || signer_public_key(32) || signature(64)
//! ```

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::AdminFact;

pub const TYPE_ADMIN: u8 = 139;
pub const FACT_BYTES: usize = 1 + 8 + (32 * 6) + ED25519_SIGNATURE_BYTES;
pub fn encode_fact(fact: &AdminFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_ADMIN, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    out[41..73].copy_from_slice(&fact.public_key);
    out[73..105].copy_from_slice(&fact.authority_fact_id);
    out[105..137].copy_from_slice(&fact.user_fact_id);
    out[137..169].copy_from_slice(&fact.signer_id);
    out[169..201].copy_from_slice(&fact.signer_public_key);
    out[201..265].copy_from_slice(&fact.signature);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

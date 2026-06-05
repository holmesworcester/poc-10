//! Canonical byte encoding for recipient key facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. It does not sign, authenticate, inspect context, or materialize rows.

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::RecipientKeyFact;

pub const TYPE_RECIPIENT_KEY: u8 = 150;
pub const RECIPIENT_KEY_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 8 + 32 + ED25519_SIGNATURE_BYTES;
pub fn encode_recipient_key(fact: &RecipientKeyFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; RECIPIENT_KEY_BYTES];
    wire::put_u8(TYPE_RECIPIENT_KEY, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.endpoint_id);
    out[65..97].copy_from_slice(&fact.recipient_key);
    out[97..129].copy_from_slice(&fact.previous_recipient_key_id);
    wire::put_u64be(fact.created_at_ms, &mut out[129..137]).map_err(wire_err)?;
    out[137..169].copy_from_slice(&fact.signer_public_key);
    out[169..233].copy_from_slice(&fact.signature);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

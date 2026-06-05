//! Canonical byte encoding for local recipient key facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, and the field validation that canonical material must satisfy. It
//! does not authenticate, inspect context, or materialize rows.

use crate::core::crypto::{self, X25519_PRIVATE_KEY_BYTES, X25519_PUBLIC_KEY_BYTES};
use crate::core::wire;

use super::fact::LocalRecipientKeyFact;

pub const TYPE_LOCAL_RECIPIENT_KEY: u8 = 156;
pub const LOCAL_RECIPIENT_KEY_BYTES: usize =
    1 + 32 + 32 + X25519_PUBLIC_KEY_BYTES + X25519_PRIVATE_KEY_BYTES;

pub fn encode_local_recipient_key(fact: &LocalRecipientKeyFact) -> Result<Vec<u8>, String> {
    validate_local_recipient_key(fact)?;
    let mut out = vec![0; LOCAL_RECIPIENT_KEY_BYTES];
    wire::put_u8(TYPE_LOCAL_RECIPIENT_KEY, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.recipient_key_id);
    out[65..97].copy_from_slice(&fact.recipient_key);
    out[97..129].copy_from_slice(&fact.recipient_secret);
    Ok(out)
}

pub(crate) fn validate_local_recipient_key(fact: &LocalRecipientKeyFact) -> Result<(), String> {
    for (name, id) in [
        ("local recipient key workspace_id", &fact.workspace_id),
        (
            "local recipient key recipient_key_id",
            &fact.recipient_key_id,
        ),
        ("local recipient key recipient_key", &fact.recipient_key),
        (
            "local recipient key recipient_secret",
            &fact.recipient_secret,
        ),
    ] {
        if id.iter().all(|byte| *byte == 0) {
            return Err(format!("{name} cannot be empty"));
        }
    }
    if crypto::x25519_public_key(&fact.recipient_secret) != fact.recipient_key {
        return Err("local recipient key secret does not match public key".to_string());
    }
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

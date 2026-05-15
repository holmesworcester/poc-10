//! Fixed-width layouts for recipient-key facts (public + local).

use super::fact::{LocalRecipientKeyFact, RecipientKeyFact};
use crate::core::crypto::{self, X25519_PRIVATE_KEY_BYTES, X25519_PUBLIC_KEY_BYTES};
use crate::core::wire;

pub const TYPE_RECIPIENT_KEY: u8 = 150;
pub const TYPE_LOCAL_RECIPIENT_KEY: u8 = 156;

pub const RECIPIENT_KEY_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 8;
pub const LOCAL_RECIPIENT_KEY_BYTES: usize =
    1 + 32 + 32 + X25519_PUBLIC_KEY_BYTES + X25519_PRIVATE_KEY_BYTES;

pub fn encode_recipient_key(fact: &RecipientKeyFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; RECIPIENT_KEY_BYTES];
    wire::put_u8(TYPE_RECIPIENT_KEY, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.endpoint_id);
    out[65..97].copy_from_slice(&fact.recipient_key);
    out[97..129].copy_from_slice(&fact.previous_recipient_key_id);
    wire::put_u64be(fact.created_at_ms, &mut out[129..137]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_recipient_key(bytes: &[u8]) -> Result<RecipientKeyFact, String> {
    wire::expect_len(bytes, RECIPIENT_KEY_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_RECIPIENT_KEY, "recipient key")?;
    Ok(RecipientKeyFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        endpoint_id: bytes[33..65].try_into().unwrap(),
        recipient_key: bytes[65..97].try_into().unwrap(),
        previous_recipient_key_id: bytes[97..129].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[129..137]).map_err(wire_err)?,
    })
}

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

pub fn decode_local_recipient_key(bytes: &[u8]) -> Result<LocalRecipientKeyFact, String> {
    wire::expect_len(bytes, LOCAL_RECIPIENT_KEY_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_LOCAL_RECIPIENT_KEY, "local recipient key")?;
    let fact = LocalRecipientKeyFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        recipient_key_id: bytes[33..65].try_into().unwrap(),
        recipient_key: bytes[65..97].try_into().unwrap(),
        recipient_secret: bytes[97..129].try_into().unwrap(),
    };
    validate_local_recipient_key(&fact)?;
    Ok(fact)
}

fn validate_local_recipient_key(fact: &LocalRecipientKeyFact) -> Result<(), String> {
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

fn expect_tag(bytes: &[u8], expected: u8, label: &str) -> Result<(), String> {
    let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {label}"))
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

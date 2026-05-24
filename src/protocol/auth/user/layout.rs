//! Fixed-width layout for user facts and rows.
//!
//! User names are stored in a fixed slot so fact ids are stable and row values
//! can be decoded without schema-dependent parsing. Encoding rejects embedded
//! NUL bytes and decoding rejects non-canonical padding. Keep those byte
//! invariants here; invite and admin authority checks belong to projection.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;
use crate::core::wire::FixedText;

use super::fact::{UserFact, Username, USERNAME_BYTES};

pub const TYPE_USER: u8 = 14;
pub const ROW_VALUE_BYTES: usize = 8 + 32 + 32 + USERNAME_BYTES;
pub const FACT_BYTES: usize = 1 + 8 + 32 + 32 + USERNAME_BYTES + 32 + 32 + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = FACT_BYTES - ED25519_SIGNATURE_BYTES;

pub fn encode_fact(fact: &UserFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_USER, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    out[41..73].copy_from_slice(&fact.public_key);
    write_username(&fact.username, &mut out[73..73 + USERNAME_BYTES])?;
    let signer_start = 73 + USERNAME_BYTES;
    out[signer_start..signer_start + 32].copy_from_slice(&fact.signer_id);
    out[signer_start + 32..signer_start + 64].copy_from_slice(&fact.signer_public_key);
    out[signer_start + 64..signer_start + 64 + ED25519_SIGNATURE_BYTES]
        .copy_from_slice(&fact.signature);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<UserFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_USER {
        return Err("expected user fact".to_string());
    }
    let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[9..41]);
    let mut public_key = [0; 32];
    public_key.copy_from_slice(&bytes[41..73]);
    let username = read_username(&bytes[73..73 + USERNAME_BYTES])?;
    let signer_start = 73 + USERNAME_BYTES;
    let mut signer_id = [0; 32];
    signer_id.copy_from_slice(&bytes[signer_start..signer_start + 32]);
    let mut signer_public_key = [0; 32];
    signer_public_key.copy_from_slice(&bytes[signer_start + 32..signer_start + 64]);
    let mut signature = [0; ED25519_SIGNATURE_BYTES];
    signature
        .copy_from_slice(&bytes[signer_start + 64..signer_start + 64 + ED25519_SIGNATURE_BYTES]);
    Ok(UserFact {
        created_at_ms,
        workspace_id,
        public_key,
        username,
        signer_id,
        signer_public_key,
        signature,
    })
}

pub fn signing_bytes(fact: &UserFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(&encode_fact(fact)?, SIGNATURE_OFFSET..FACT_BYTES)
        .map_err(wire_err)
}

pub fn verify_signature(fact: &UserFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "user",
    )
}

/// Encodes the projection row value: `created_at(8) || public_key(32) || user_invite_id(32) || username(64)`.
pub(crate) fn encode_row_value(
    user_invite_id: &[u8; 32],
    fact: &UserFact,
) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ROW_VALUE_BYTES];
    wire::put_u64be(fact.created_at_ms, &mut out[0..8]).map_err(wire_err)?;
    out[8..40].copy_from_slice(&fact.public_key);
    out[40..72].copy_from_slice(user_invite_id);
    write_username(&fact.username, &mut out[72..])?;
    Ok(out)
}

pub(crate) fn decode_row_value(value: &[u8]) -> Result<DecodedRowValue, String> {
    wire::expect_len(value, ROW_VALUE_BYTES).map_err(wire_err)?;
    let created_at_ms = wire::take_u64be(&value[0..8]).map_err(wire_err)?;
    let mut public_key = [0; 32];
    public_key.copy_from_slice(&value[8..40]);
    let mut user_invite_id = [0; 32];
    user_invite_id.copy_from_slice(&value[40..72]);
    let username = read_username(&value[72..])?;
    Ok(DecodedRowValue {
        created_at_ms,
        public_key,
        user_invite_id,
        username: username.to_string(),
    })
}

pub(crate) struct DecodedRowValue {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_invite_id: [u8; 32],
    pub username: String,
}

fn write_username(username: &Username, out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, USERNAME_BYTES).map_err(wire_err)?;
    out.copy_from_slice(username.padded_bytes());
    Ok(())
}

fn read_username(bytes: &[u8]) -> Result<Username, String> {
    let padded: [u8; USERNAME_BYTES] = bytes
        .try_into()
        .map_err(|_| "username slot has wrong length".to_string())?;
    FixedText::from_padded(padded).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> UserFact {
        UserFact {
            created_at_ms: 42,
            workspace_id: [2; 32],
            public_key: [7; 32],
            username: Username::new("alice").expect("username"),
            signer_id: [8; 32],
            signer_public_key: [9; 32],
            signature: [10; ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn user_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn row_value_roundtrip() {
        let value = encode_row_value(&[9; 32], &fact()).expect("row value");
        let decoded = decode_row_value(&value).expect("decode row");
        assert_eq!(decoded.created_at_ms, 42);
        assert_eq!(decoded.public_key, [7; 32]);
        assert_eq!(decoded.user_invite_id, [9; 32]);
        assert_eq!(decoded.username, "alice");
    }

    #[test]
    fn rejects_non_canonical_username_padding() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        let start = 1 + 8 + 32 + 32;
        encoded[start + "alice".len() + 1] = b'x';
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_long_username() {
        let err =
            Username::new(&"a".repeat(USERNAME_BYTES + 1)).expect_err("long username must fail");
        assert_eq!(
            err,
            wire::WireError::ValueTooLarge {
                max: USERNAME_BYTES,
                actual: USERNAME_BYTES + 1
            }
        );
    }
}

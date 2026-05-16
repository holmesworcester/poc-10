//! Fixed-width user fact and projection-row layout.

use crate::core::wire;
use crate::core::wire::FixedSlot;

use super::fact::{UserFact, USERNAME_BYTES};

pub const TYPE_USER: u8 = 14;
pub const ROW_VALUE_BYTES: usize = 8 + 32 + 32 + USERNAME_BYTES;
pub const FACT_BYTES: usize = 1 + 8 + 32 + 32 + USERNAME_BYTES;

pub fn encode_fact(fact: &UserFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_USER, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    out[41..73].copy_from_slice(&fact.public_key);
    write_username(&fact.username, &mut out[73..])?;
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
    let username = read_username(&bytes[73..])?;
    Ok(UserFact {
        created_at_ms,
        workspace_id,
        public_key,
        username,
    })
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
        username,
    })
}

pub(crate) struct DecodedRowValue {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],
    pub user_invite_id: [u8; 32],
    pub username: String,
}

fn write_username(username: &str, out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, USERNAME_BYTES).map_err(wire_err)?;
    if username.as_bytes().contains(&0) {
        return Err("username cannot contain NUL".to_string());
    }
    let slot = FixedSlot::<USERNAME_BYTES>::new(username.as_bytes()).map_err(wire_err)?;
    out.copy_from_slice(slot.padded_bytes());
    Ok(())
}

fn read_username(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err("username has non-canonical padding".to_string());
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| "username is not valid utf-8".to_string())
        .map(ToOwned::to_owned)
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
            username: "alice".to_string(),
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
        let err = encode_fact(&UserFact {
            created_at_ms: 1,
            workspace_id: [0; 32],
            public_key: [0; 32],
            username: "a".repeat(USERNAME_BYTES + 1),
        })
        .expect_err("long username must fail");
        assert!(
            err.contains("ValueTooLarge") || err.contains("too"),
            "{err}"
        );
    }
}

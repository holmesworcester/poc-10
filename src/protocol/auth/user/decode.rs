//! Byte decoding for user facts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and
//! canonical username padding. Id checks live in
//! `authenticate.rs`.

use crate::core::wire;
use crate::core::wire::FixedText;

use super::encode::{FACT_BYTES, TYPE_USER};
use super::fact::{UserFact, Username, USERNAME_BYTES};

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
    Ok(UserFact {
        created_at_ms,
        workspace_id,
        public_key,
        username,
        signer_id,
        signer_public_key,
    })
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
    use crate::protocol::auth::user::encode::{encode_fact, FACT_BYTES};

    fn fact() -> UserFact {
        UserFact {
            created_at_ms: 42,
            workspace_id: [2; 32],
            public_key: [7; 32],
            username: Username::new("alice").expect("username"),
            signer_id: [8; 32],
            signer_public_key: [9; 32],
        }
    }

    #[test]
    fn user_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
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

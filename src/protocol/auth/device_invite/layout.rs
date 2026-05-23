//! Fixed-width layout for device-invite facts and rows.
//!
//! Device invites authorize an additional endpoint for an existing user. The
//! layout keeps the optional user-invite link canonical by storing all-zeroes
//! for `None`, and the row value mirrors the fields projection needs for later
//! endpoint admission. Keep byte shape here and invite authority checks in the
//! device-invite projector.

use crate::core::wire;

use super::fact::DeviceInviteFact;

pub const TYPE_DEVICE_INVITE: u8 = 134;
/// Layout: `type(1) || created_at_ms(8) || workspace_id(32) ||
/// user_authority_fact_id(32) || user_invite_fact_id_or_zero(32) ||
/// public_key(32)`.
pub const FACT_BYTES: usize = 1 + 8 + 32 + 32 + 32 + 32;
/// Row value layout: `created_at_ms(8) || user_authority_fact_id(32) ||
/// user_invite_fact_id_or_zero(32) || public_key(32)`.
pub const ROW_VALUE_BYTES: usize = 8 + 32 + 32 + 32;

pub fn encode_fact(fact: &DeviceInviteFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_DEVICE_INVITE, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    out[41..73].copy_from_slice(&fact.user_authority_fact_id);
    out[73..105].copy_from_slice(&fact.user_invite_fact_id.unwrap_or([0; 32]));
    out[105..137].copy_from_slice(&fact.public_key);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<DeviceInviteFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_DEVICE_INVITE {
        return Err("expected device_invite fact".to_string());
    }
    let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[9..41]);
    let mut user_authority_fact_id = [0; 32];
    user_authority_fact_id.copy_from_slice(&bytes[41..73]);
    let mut user_invite_raw = [0; 32];
    user_invite_raw.copy_from_slice(&bytes[73..105]);
    let user_invite_fact_id = if user_invite_raw == [0; 32] {
        None
    } else {
        Some(user_invite_raw)
    };
    let mut public_key = [0; 32];
    public_key.copy_from_slice(&bytes[105..137]);
    Ok(DeviceInviteFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id,
        user_invite_fact_id,
        public_key,
    })
}

pub(crate) fn encode_row_value(fact: &DeviceInviteFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ROW_VALUE_BYTES];
    wire::put_u64be(fact.created_at_ms, &mut out[0..8]).map_err(wire_err)?;
    out[8..40].copy_from_slice(&fact.user_authority_fact_id);
    out[40..72].copy_from_slice(&fact.user_invite_fact_id.unwrap_or([0; 32]));
    out[72..104].copy_from_slice(&fact.public_key);
    Ok(out)
}

pub(crate) fn decode_row_value(value: &[u8]) -> Result<DecodedRowValue, String> {
    wire::expect_len(value, ROW_VALUE_BYTES).map_err(wire_err)?;
    let created_at_ms = wire::take_u64be(&value[0..8]).map_err(wire_err)?;
    let mut user_authority_fact_id = [0; 32];
    user_authority_fact_id.copy_from_slice(&value[8..40]);
    let mut user_invite_raw = [0; 32];
    user_invite_raw.copy_from_slice(&value[40..72]);
    let user_invite_fact_id = if user_invite_raw == [0; 32] {
        None
    } else {
        Some(user_invite_raw)
    };
    let mut public_key = [0; 32];
    public_key.copy_from_slice(&value[72..104]);
    Ok(DecodedRowValue {
        created_at_ms,
        user_authority_fact_id,
        user_invite_fact_id,
        public_key,
    })
}

pub(crate) struct DecodedRowValue {
    pub created_at_ms: u64,
    pub user_authority_fact_id: [u8; 32],
    pub user_invite_fact_id: Option<[u8; 32]>,
    pub public_key: [u8; 32],
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> DeviceInviteFact {
        DeviceInviteFact {
            created_at_ms: 11,
            workspace_id: [1; 32],
            user_authority_fact_id: [2; 32],
            user_invite_fact_id: Some([4; 32]),
            public_key: [3; 32],
        }
    }

    #[test]
    fn device_invite_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn zero_user_invite_roundtrips_as_none() {
        let event = DeviceInviteFact {
            user_invite_fact_id: None,
            ..fact()
        };
        let encoded = encode_fact(&event).expect("encode");
        assert_eq!(decode_fact(&encoded).expect("decode"), event);
    }

    #[test]
    fn row_value_roundtrip() {
        let value = encode_row_value(&fact()).expect("row value");
        let decoded = decode_row_value(&value).expect("decode row");
        assert_eq!(decoded.created_at_ms, 11);
        assert_eq!(decoded.user_authority_fact_id, [2; 32]);
        assert_eq!(decoded.user_invite_fact_id, Some([4; 32]));
        assert_eq!(decoded.public_key, [3; 32]);
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = 0;
        assert!(decode_fact(&encoded).is_err());
    }
}

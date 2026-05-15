//! Fixed-width disappearing-messages setting fact layout.
//!
//! Body shape:
//!
//! ```text
//! tag(1) || created_at_ms(8) || workspace_id(32) || scope_kind(1)
//!        || scope_id(32) || author_user_id(32) || ttl_minutes(4)
//!        || retire_minute(8) || supersedes_setting_id(32)
//! ```
//!
//! `supersedes_setting_id` uses an all-zero sentinel to encode the
//! `None` variant (first setting in the scope's chain).

use crate::core::wire;

use super::fact::DisappearingMessagesSettingFact;

pub const TYPE_DISAPPEARING_MESSAGES_SETTING: u8 = 147;

pub const FACT_BYTES: usize = 1 + 8 + 32 + 1 + 32 + 32 + 4 + 8 + 32;

pub const NO_PREVIOUS_SETTING_ID: [u8; 32] = [0; 32];

pub fn encode_fact(fact: &DisappearingMessagesSettingFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_DISAPPEARING_MESSAGES_SETTING, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    wire::put_u8(fact.scope_kind, &mut out[41..42]).map_err(wire_err)?;
    out[42..74].copy_from_slice(&fact.scope_id);
    out[74..106].copy_from_slice(&fact.author_user_id);
    wire::put_u32be(fact.ttl_minutes, &mut out[106..110]).map_err(wire_err)?;
    wire::put_u64be(fact.retire_minute, &mut out[110..118]).map_err(wire_err)?;
    let supersedes = fact
        .supersedes_setting_id
        .unwrap_or(NO_PREVIOUS_SETTING_ID);
    out[118..150].copy_from_slice(&supersedes);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<DisappearingMessagesSettingFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_DISAPPEARING_MESSAGES_SETTING {
        return Err("expected disappearing_messages_setting fact".to_string());
    }
    let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[9..41]);
    let scope_kind = wire::take_u8(&bytes[41..42]).map_err(wire_err)?;
    let mut scope_id = [0; 32];
    scope_id.copy_from_slice(&bytes[42..74]);
    let mut author_user_id = [0; 32];
    author_user_id.copy_from_slice(&bytes[74..106]);
    let ttl_minutes = wire::take_u32be(&bytes[106..110]).map_err(wire_err)?;
    let retire_minute = wire::take_u64be(&bytes[110..118]).map_err(wire_err)?;
    let mut supersedes_raw = [0; 32];
    supersedes_raw.copy_from_slice(&bytes[118..150]);
    let supersedes_setting_id = if supersedes_raw == NO_PREVIOUS_SETTING_ID {
        None
    } else {
        Some(supersedes_raw)
    };
    Ok(DisappearingMessagesSettingFact {
        workspace_id,
        supersedes_setting_id,
        ttl_minutes,
        retire_minute,
        scope_kind,
        scope_id,
        author_user_id,
        created_at_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> DisappearingMessagesSettingFact {
        DisappearingMessagesSettingFact {
            workspace_id: [1; 32],
            supersedes_setting_id: Some([7; 32]),
            ttl_minutes: 60,
            retire_minute: 12_345,
            scope_kind: super::super::fact::SCOPE_KIND_WORKSPACE,
            scope_id: [1; 32],
            author_user_id: [3; 32],
            created_at_ms: 6_000_000,
        }
    }

    #[test]
    fn setting_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn none_supersedes_uses_zero_sentinel() {
        let mut f = fact();
        f.supersedes_setting_id = None;
        let encoded = encode_fact(&f).expect("encode");
        assert_eq!(&encoded[118..150], &NO_PREVIOUS_SETTING_ID);
        assert_eq!(decode_fact(&encoded).expect("decode"), f);
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_DISAPPEARING_MESSAGES_SETTING.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_fact(&[TYPE_DISAPPEARING_MESSAGES_SETTING; 16]).is_err());
    }
}

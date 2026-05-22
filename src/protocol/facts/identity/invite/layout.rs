//! Fixed-width invite-secret fact and projection-row layout.
//!
//! Invite secrets are local bootstrap capabilities. Their durable bytes store
//! only the bootstrap hash, secret material, and optional scoped workspace and
//! invite ids. Network route information comes from daemon listen-address state
//! and connection/request facts, not from this payload.

use crate::core::wire;

use super::fact::InviteSecretFact;

pub const TYPE_INVITE_SECRET: u8 = 129;
/// Layout: `type(1) || bootstrap_hash(32) || bootstrap_secret(32) ||
/// workspace_id_or_zero(32) || invite_fact_id_or_zero(32)`.
pub const FACT_BYTES: usize = 1 + 32 + 32 + 32 + 32;
/// Row value layout: `bootstrap_secret(32) || workspace_id_or_zero(32) ||
/// invite_fact_id_or_zero(32)`.
pub const ROW_VALUE_BYTES: usize = 32 + 32 + 32;

pub fn encode_fact(fact: &InviteSecretFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_INVITE_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.bootstrap_hash);
    out[33..65].copy_from_slice(&fact.bootstrap_secret);
    out[65..97].copy_from_slice(&fact.workspace_id.unwrap_or([0; 32]));
    out[97..129].copy_from_slice(&fact.invite_fact_id.unwrap_or([0; 32]));
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<InviteSecretFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_INVITE_SECRET {
        return Err("expected invite_secret fact".to_string());
    }
    let mut bootstrap_hash = [0; 32];
    bootstrap_hash.copy_from_slice(&bytes[1..33]);
    let mut bootstrap_secret = [0; 32];
    bootstrap_secret.copy_from_slice(&bytes[33..65]);
    let mut workspace_raw = [0; 32];
    workspace_raw.copy_from_slice(&bytes[65..97]);
    let mut invite_raw = [0; 32];
    invite_raw.copy_from_slice(&bytes[97..129]);
    let workspace_id = optional_id(workspace_raw);
    let invite_fact_id = optional_id(invite_raw);
    InviteSecretFact {
        bootstrap_hash,
        bootstrap_secret,
        workspace_id,
        invite_fact_id,
    }
    .validate()
}

pub(crate) fn encode_row_value(fact: &InviteSecretFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ROW_VALUE_BYTES];
    out[0..32].copy_from_slice(&fact.bootstrap_secret);
    out[32..64].copy_from_slice(&fact.workspace_id.unwrap_or([0; 32]));
    out[64..96].copy_from_slice(&fact.invite_fact_id.unwrap_or([0; 32]));
    Ok(out)
}

pub(crate) fn decode_row_value(value: &[u8]) -> Result<DecodedRowValue, String> {
    wire::expect_len(value, ROW_VALUE_BYTES).map_err(wire_err)?;
    let mut bootstrap_secret = [0; 32];
    bootstrap_secret.copy_from_slice(&value[0..32]);
    let mut workspace_raw = [0; 32];
    workspace_raw.copy_from_slice(&value[32..64]);
    let mut invite_raw = [0; 32];
    invite_raw.copy_from_slice(&value[64..96]);
    Ok(DecodedRowValue {
        bootstrap_secret,
        workspace_id: optional_id(workspace_raw),
        invite_fact_id: optional_id(invite_raw),
    })
}

pub(crate) struct DecodedRowValue {
    pub bootstrap_secret: [u8; 32],
    pub workspace_id: Option<[u8; 32]>,
    pub invite_fact_id: Option<[u8; 32]>,
}

fn optional_id(id: [u8; 32]) -> Option<[u8; 32]> {
    if id == [0; 32] {
        None
    } else {
        Some(id)
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_secret_fact_roundtrips_fixed_width() {
        let fact = InviteSecretFact::new([7; 32]);
        let encoded = encode_fact(&fact).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }

    #[test]
    fn invite_secret_fact_roundtrips_scoped() {
        let fact = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
        let encoded = encode_fact(&fact).expect("encode");
        let decoded = decode_fact(&encoded).expect("decode");
        assert_eq!(decoded.workspace_id, Some([1; 32]));
        assert_eq!(decoded.invite_fact_id, Some([2; 32]));
    }

    #[test]
    fn decode_rejects_incomplete_scope() {
        let fact = InviteSecretFact {
            workspace_id: Some([1; 32]),
            ..InviteSecretFact::new([7; 32])
        };
        let encoded = encode_fact(&fact).expect("encode");
        let err = decode_fact(&encoded).expect_err("incomplete scope must fail");
        assert_eq!(err, "invite secret scope is incomplete");
    }

    #[test]
    fn decode_rejects_hash_secret_mismatch() {
        let fact = InviteSecretFact {
            bootstrap_hash: [9; 32],
            bootstrap_secret: [7; 32],
            workspace_id: None,
            invite_fact_id: None,
        };
        let encoded = encode_fact(&fact).expect("encode");
        let err = decode_fact(&encoded).expect_err("mismatched hash must fail");
        assert_eq!(err, "invite secret hash does not match secret");
    }

    #[test]
    fn row_value_roundtrip() {
        let fact = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
        let value = encode_row_value(&fact).expect("encode row");
        let decoded = decode_row_value(&value).expect("decode row");
        assert_eq!(decoded.bootstrap_secret, [7; 32]);
        assert_eq!(decoded.workspace_id, Some([1; 32]));
        assert_eq!(decoded.invite_fact_id, Some([2; 32]));
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&InviteSecretFact::new([7; 32])).expect("encode");
        encoded[0] = 0;
        assert!(decode_fact(&encoded).is_err());
    }
}

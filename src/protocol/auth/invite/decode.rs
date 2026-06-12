//! Byte decoding for invite-secret facts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and the
//! internally consistent hash/scope fields. Id checks live in
//! `authenticate.rs`.

use crate::core::wire;

use super::encode::{FACT_BYTES, TYPE_INVITE_SECRET};
use super::fact::InviteSecretFact;

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
    use crate::protocol::auth::invite::encode::{encode_fact, FACT_BYTES};

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
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&InviteSecretFact::new([7; 32])).expect("encode");
        encoded[0] = 0;
        assert!(decode_fact(&encoded).is_err());
    }
}

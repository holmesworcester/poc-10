//! Byte decoding for retention policy facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! id checks live in `authenticate.rs`.

use crate::core::wire;

use super::encode::{FACT_BYTES, NO_PREVIOUS_POLICY_ID, TYPE_RETENTION_POLICY};
use super::fact::RetentionPolicyFact;

pub fn decode_fact(bytes: &[u8]) -> Result<RetentionPolicyFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_RETENTION_POLICY {
        return Err("expected content::retention_policy fact".to_string());
    }
    let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[9..41]);
    let scope_kind = wire::take_u8(&bytes[41..42]).map_err(wire_err)?;
    let mut scope_id = [0; 32];
    scope_id.copy_from_slice(&bytes[42..74]);
    let mut author_user_id = [0; 32];
    author_user_id.copy_from_slice(&bytes[74..106]);
    let mut signer_id = [0; 32];
    signer_id.copy_from_slice(&bytes[106..138]);
    let mut signer_public_key = [0; 32];
    signer_public_key.copy_from_slice(&bytes[138..170]);
    let ttl_minutes = wire::take_u32be(&bytes[170..174]).map_err(wire_err)?;
    let retire_minute = wire::take_u64be(&bytes[174..182]).map_err(wire_err)?;
    let mut supersedes_raw = [0; 32];
    supersedes_raw.copy_from_slice(&bytes[182..214]);
    let supersedes_policy_id = if supersedes_raw == NO_PREVIOUS_POLICY_ID {
        None
    } else {
        Some(supersedes_raw)
    };
    Ok(RetentionPolicyFact {
        workspace_id,
        supersedes_policy_id,
        ttl_minutes,
        retire_minute,
        scope_kind,
        scope_id,
        author_user_id,
        signer_id,
        signer_public_key,
        created_at_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::content::retention_policy::encode::{
        encode_fact, FACT_BYTES, NO_PREVIOUS_POLICY_ID, TYPE_RETENTION_POLICY,
    };

    fn fact() -> RetentionPolicyFact {
        RetentionPolicyFact {
            workspace_id: [1; 32],
            supersedes_policy_id: Some([7; 32]),
            ttl_minutes: 60,
            retire_minute: 12_345,
            scope_kind: crate::protocol::content::retention_policy::fact::SCOPE_KIND_WORKSPACE,
            scope_id: [1; 32],
            author_user_id: [3; 32],
            signer_id: [9; 32],
            signer_public_key: [10; 32],
            created_at_ms: 6_000_000,
        }
    }

    #[test]
    fn retention_policy_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn none_supersedes_uses_zero_sentinel() {
        let mut f = fact();
        f.supersedes_policy_id = None;
        let encoded = encode_fact(&f).expect("encode");
        assert_eq!(&encoded[182..214], &NO_PREVIOUS_POLICY_ID);
        assert_eq!(decode_fact(&encoded).expect("decode"), f);
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_RETENTION_POLICY.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_fact(&[TYPE_RETENTION_POLICY; 16]).is_err());
    }
}

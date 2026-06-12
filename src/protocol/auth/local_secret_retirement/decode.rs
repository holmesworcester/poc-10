//! Byte decoding for local secret-retirement facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order, then
//! re-runs field validation to reject non-canonical facts. Id checks live in
//! `authenticate.rs`.

use crate::core::wire;

use super::encode::{validate_fact, LOCAL_SECRET_RETIREMENT_BYTES, TYPE_LOCAL_SECRET_RETIREMENT};
use super::fact::LocalSecretRetirementFact;

pub fn decode_fact(bytes: &[u8]) -> Result<LocalSecretRetirementFact, String> {
    wire::expect_len(bytes, LOCAL_SECRET_RETIREMENT_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_LOCAL_SECRET_RETIREMENT {
        return Err("expected local secret retirement".to_string());
    }
    let fact = LocalSecretRetirementFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        target_secret_id: bytes[33..65].try_into().unwrap(),
        reason_kind: wire::take_u8(&bytes[65..66]).map_err(wire_err)?,
        floor_minute: wire::take_u64be(&bytes[66..74]).map_err(wire_err)?,
        created_at_ms: wire::take_u64be(&bytes[74..82]).map_err(wire_err)?,
    };
    validate_fact(&fact)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::local_secret_retirement::encode::{
        encode_fact, LOCAL_SECRET_RETIREMENT_BYTES,
    };
    use crate::protocol::auth::local_secret_retirement::fact::RETIRE_REASON_CHOP;

    fn sample_fact() -> LocalSecretRetirementFact {
        LocalSecretRetirementFact {
            workspace_id: [1; 32],
            target_secret_id: [2; 32],
            reason_kind: RETIRE_REASON_CHOP,
            floor_minute: 10,
            created_at_ms: 123,
        }
    }

    #[test]
    fn local_secret_retirement_roundtrips_fixed_width() {
        let fact = sample_fact();

        let encoded = encode_fact(&fact).expect("encode local secret retirement");

        assert_eq!(encoded.len(), LOCAL_SECRET_RETIREMENT_BYTES);
        assert_eq!(
            decode_fact(&encoded).expect("decode local secret retirement"),
            fact
        );
    }
}

//! Fixed-width layout for local secret-retirement facts.

use crate::core::wire;

use super::fact::{LocalSecretRetirementFact, RETIRE_REASON_CHOP};

pub const TYPE_LOCAL_SECRET_RETIREMENT: u8 = 157;
pub const LOCAL_SECRET_RETIREMENT_BYTES: usize = 1 + 32 + 32 + 1 + 8 + 8;

pub fn encode_fact(fact: &LocalSecretRetirementFact) -> Result<Vec<u8>, String> {
    validate_fact(fact)?;
    let mut out = vec![0; LOCAL_SECRET_RETIREMENT_BYTES];
    wire::put_u8(TYPE_LOCAL_SECRET_RETIREMENT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.target_secret_id);
    wire::put_u8(fact.reason_kind, &mut out[65..66]).map_err(wire_err)?;
    wire::put_u64be(fact.floor_minute, &mut out[66..74]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[74..82]).map_err(wire_err)?;
    Ok(out)
}

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

fn validate_fact(fact: &LocalSecretRetirementFact) -> Result<(), String> {
    if fact.workspace_id.iter().all(|byte| *byte == 0) {
        return Err("local secret retirement workspace_id cannot be empty".to_string());
    }
    if fact.target_secret_id.iter().all(|byte| *byte == 0) {
        return Err("local secret retirement target_secret_id cannot be empty".to_string());
    }
    if fact.reason_kind != RETIRE_REASON_CHOP {
        return Err("local secret retirement reason is unsupported".to_string());
    }
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

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

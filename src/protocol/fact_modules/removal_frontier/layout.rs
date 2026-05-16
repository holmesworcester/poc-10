//! Fixed-width codec for `RemovalFrontierFact`.
//!
//! Each frontier carries up to `MAX_REMOVAL_FACT_REFS` refs and always encodes
//! to the same byte length by zero-filling unused slots. Decoders reject
//! variable-size history lists; commands build additional frontier facts when
//! the logical removal boundary needs more fan-in. The encoded ref count
//! (`u8`) and the slot count together let canonical bytes stay fixed-width
//! while a variable number of refs are decodable.

use crate::core::facts::FactId;
use crate::core::wire;
use crate::core::wire::{FixedLayout, U64be, U8};

use super::fact::{RemovalFrontierFact, MAX_REMOVAL_FACT_REFS};

pub const TYPE_REMOVAL_FRONTIER: u8 = 30;
pub const FACT_BYTES: usize = 1 + 32 + U64be::LEN + 32 + U8::LEN + 32 * MAX_REMOVAL_FACT_REFS;
pub const ROW_VALUE_BYTES: usize = U64be::LEN + 32 + U8::LEN + 32 * MAX_REMOVAL_FACT_REFS;

pub fn encode_fact(fact: &RemovalFrontierFact) -> Result<Vec<u8>, String> {
    validate(fact)?;
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_REMOVAL_FRONTIER, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    wire::put_u64be(fact.created_at_ms, &mut out[33..41]).map_err(wire_err)?;
    out[41..73].copy_from_slice(&fact.authority_admin_id);
    let count = u8::try_from(fact.removal_fact_ids.len())
        .map_err(|_| "removal frontier has too many refs".to_string())?;
    wire::put_u8(count, &mut out[73..74]).map_err(wire_err)?;
    write_refs(&fact.removal_fact_ids, &mut out[74..])?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<RemovalFrontierFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_REMOVAL_FRONTIER {
        return Err("expected removal frontier fact".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[1..33]);
    let created_at_ms = wire::take_u64be(&bytes[33..41]).map_err(wire_err)?;
    let mut authority_admin_id = [0; 32];
    authority_admin_id.copy_from_slice(&bytes[41..73]);
    let count = wire::take_u8(&bytes[73..74]).map_err(wire_err)? as usize;
    if count > MAX_REMOVAL_FACT_REFS {
        return Err("removal frontier has too many refs".to_string());
    }
    let refs = read_refs(&bytes[74..], count)?;
    let fact = RemovalFrontierFact {
        workspace_id,
        created_at_ms,
        authority_admin_id,
        removal_fact_ids: refs,
    };
    validate(&fact)?;
    Ok(fact)
}

pub(crate) fn encode_row_value(fact: &RemovalFrontierFact) -> Result<Vec<u8>, String> {
    validate(fact)?;
    let mut out = vec![0; ROW_VALUE_BYTES];
    wire::put_u64be(fact.created_at_ms, &mut out[0..8]).map_err(wire_err)?;
    out[8..40].copy_from_slice(&fact.authority_admin_id);
    let count = u8::try_from(fact.removal_fact_ids.len())
        .map_err(|_| "removal frontier row has too many refs".to_string())?;
    wire::put_u8(count, &mut out[40..41]).map_err(wire_err)?;
    write_refs(&fact.removal_fact_ids, &mut out[41..])?;
    Ok(out)
}

pub(crate) struct DecodedRowValue {
    pub created_at_ms: u64,
    pub authority_admin_id: FactId,
    pub removal_fact_ids: Vec<FactId>,
}

pub(crate) fn decode_row_value(value: &[u8]) -> Result<DecodedRowValue, String> {
    wire::expect_len(value, ROW_VALUE_BYTES).map_err(wire_err)?;
    let created_at_ms = wire::take_u64be(&value[0..8]).map_err(wire_err)?;
    let mut authority_admin_id = [0; 32];
    authority_admin_id.copy_from_slice(&value[8..40]);
    let count = wire::take_u8(&value[40..41]).map_err(wire_err)? as usize;
    if count > MAX_REMOVAL_FACT_REFS {
        return Err("removal frontier row has too many refs".to_string());
    }
    let refs = read_refs(&value[41..], count)?;
    Ok(DecodedRowValue {
        created_at_ms,
        authority_admin_id,
        removal_fact_ids: refs,
    })
}

fn write_refs(refs: &[FactId], out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, 32 * MAX_REMOVAL_FACT_REFS).map_err(wire_err)?;
    for (idx, id) in refs.iter().enumerate() {
        out[idx * 32..(idx + 1) * 32].copy_from_slice(id);
    }
    Ok(())
}

fn read_refs(bytes: &[u8], count: usize) -> Result<Vec<FactId>, String> {
    wire::expect_len(bytes, 32 * MAX_REMOVAL_FACT_REFS).map_err(wire_err)?;
    let mut out = Vec::with_capacity(count);
    for idx in 0..MAX_REMOVAL_FACT_REFS {
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[idx * 32..(idx + 1) * 32]);
        if idx < count {
            out.push(id);
        } else if id.iter().any(|byte| *byte != 0) {
            return Err("removal frontier unused ref slots must be empty".to_string());
        }
    }
    Ok(out)
}

fn validate(fact: &RemovalFrontierFact) -> Result<(), String> {
    if fact.removal_fact_ids.len() > MAX_REMOVAL_FACT_REFS {
        return Err("removal frontier has too many refs".to_string());
    }
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> RemovalFrontierFact {
        RemovalFrontierFact {
            workspace_id: [1; 32],
            created_at_ms: 1234,
            authority_admin_id: [2; 32],
            removal_fact_ids: vec![[3; 32], [4; 32]],
        }
    }

    #[test]
    fn removal_frontier_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn removal_frontier_rejects_too_many_refs() {
        let bad = RemovalFrontierFact {
            workspace_id: [1; 32],
            created_at_ms: 0,
            authority_admin_id: [2; 32],
            removal_fact_ids: vec![[0; 32]; MAX_REMOVAL_FACT_REFS + 1],
        };
        assert!(encode_fact(&bad).is_err());
    }

    #[test]
    fn removal_frontier_rejects_non_zero_unused_slots() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        let last_slot = FACT_BYTES - 1;
        bytes[last_slot] = 9;
        assert!(decode_fact(&bytes).is_err());
    }

    #[test]
    fn row_value_roundtrip() {
        let value = encode_row_value(&fact()).expect("row value");
        let decoded = decode_row_value(&value).expect("decode row");
        assert_eq!(decoded.created_at_ms, 1234);
        assert_eq!(decoded.authority_admin_id, [2; 32]);
        assert_eq!(decoded.removal_fact_ids, vec![[3; 32], [4; 32]]);
    }
}

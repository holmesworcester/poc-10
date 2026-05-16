//! Fixed-width codec for local history range-node secrets.
//!
//! Canonical bytes carry an explicit `(range_start, range_width, bit_depth,
//! event_id_prefix)` coordinate so the projector can address time-tree
//! internals (`bit_depth = 0, event_id_prefix = 0`), minute_nodes
//! (`bit_depth = 0, range_width = 1`), trie internals (`1..=255`) and trie
//! leaves (`bit_depth = TRIE_LEAF_BIT_DEPTH`) without changing wire shape.
//!
//! The encoded `event_id_prefix` is always masked to `bit_depth` so equal
//! coordinates encode equal bytes.

use crate::core::wire;
use crate::core::wire::{FixedLayout, U16be, U64be};

use super::fact::{
    mask_prefix_to_depth, LocalHistoryNodeSecretFact, NODE_SECRET_BYTES, TRIE_LEAF_BIT_DEPTH,
};

pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = 31;
pub const FACT_BYTES: usize =
    1 + 32 + 32 + 32 + U64be::LEN + U64be::LEN + U16be::LEN + 32 + 32 + NODE_SECRET_BYTES;
pub const ROW_VALUE_BYTES: usize = 32 + 32 + NODE_SECRET_BYTES;

pub fn encode_fact(fact: &LocalHistoryNodeSecretFact) -> Result<Vec<u8>, String> {
    validate(fact)?;
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_LOCAL_HISTORY_NODE_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.removal_frontier_id);
    out[65..97].copy_from_slice(&fact.source_secret_id);
    wire::put_u64be(fact.range_start, &mut out[97..105]).map_err(wire_err)?;
    wire::put_u64be(fact.range_width, &mut out[105..113]).map_err(wire_err)?;
    wire::put_u16be(fact.bit_depth, &mut out[113..115]).map_err(wire_err)?;
    out[115..147].copy_from_slice(&mask_prefix_to_depth(fact.event_id_prefix, fact.bit_depth));
    out[147..179].copy_from_slice(&fact.tombstone_node_id);
    out[179..179 + NODE_SECRET_BYTES].copy_from_slice(&fact.node_secret);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<LocalHistoryNodeSecretFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_LOCAL_HISTORY_NODE_SECRET {
        return Err("expected local history node secret fact".to_string());
    }
    let fact = LocalHistoryNodeSecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        removal_frontier_id: bytes[33..65].try_into().unwrap(),
        source_secret_id: bytes[65..97].try_into().unwrap(),
        range_start: wire::take_u64be(&bytes[97..105]).map_err(wire_err)?,
        range_width: wire::take_u64be(&bytes[105..113]).map_err(wire_err)?,
        bit_depth: wire::take_u16be(&bytes[113..115]).map_err(wire_err)?,
        event_id_prefix: bytes[115..147].try_into().unwrap(),
        tombstone_node_id: bytes[147..179].try_into().unwrap(),
        node_secret: bytes[179..179 + NODE_SECRET_BYTES].try_into().unwrap(),
    };
    validate(&fact)?;
    if mask_prefix_to_depth(fact.event_id_prefix, fact.bit_depth) != fact.event_id_prefix {
        return Err(
            "local history node secret event_id_prefix is not masked to bit_depth".to_string(),
        );
    }
    Ok(fact)
}

pub(crate) fn encode_row_value(
    local_history_node_secret_id: &[u8; 32],
    fact: &LocalHistoryNodeSecretFact,
) -> Result<Vec<u8>, String> {
    validate(fact)?;
    let mut out = vec![0; ROW_VALUE_BYTES];
    out[0..32].copy_from_slice(local_history_node_secret_id);
    out[32..64].copy_from_slice(&fact.tombstone_node_id);
    out[64..64 + NODE_SECRET_BYTES].copy_from_slice(&fact.node_secret);
    Ok(out)
}

pub(crate) struct DecodedRowValue {
    pub local_history_node_secret_id: [u8; 32],
    pub tombstone_node_id: [u8; 32],
    pub node_secret: [u8; NODE_SECRET_BYTES],
}

pub(crate) fn decode_row_value(value: &[u8]) -> Result<DecodedRowValue, String> {
    wire::expect_len(value, ROW_VALUE_BYTES).map_err(wire_err)?;
    Ok(DecodedRowValue {
        local_history_node_secret_id: value[0..32].try_into().unwrap(),
        tombstone_node_id: value[32..64].try_into().unwrap(),
        node_secret: value[64..64 + NODE_SECRET_BYTES].try_into().unwrap(),
    })
}

fn validate(fact: &LocalHistoryNodeSecretFact) -> Result<(), String> {
    if fact.range_width == 0 {
        return Err("local history node range_width must be non-zero".to_string());
    }
    if !fact.range_width.is_power_of_two() {
        return Err("local history node range_width must be a power of two".to_string());
    }
    if fact.bit_depth > TRIE_LEAF_BIT_DEPTH {
        return Err("local history node bit_depth out of range".to_string());
    }
    if fact.bit_depth != 0 && fact.range_width != 1 {
        return Err("local history node trie nodes must have range_width = 1".to_string());
    }
    if fact.node_secret.iter().all(|byte| *byte == 0) {
        return Err("local history node secret material cannot be empty".to_string());
    }
    if fact.source_secret_id.iter().all(|byte| *byte == 0) {
        return Err("local history node source_secret_id cannot be empty".to_string());
    }
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minute_node_fact() -> LocalHistoryNodeSecretFact {
        LocalHistoryNodeSecretFact {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            source_secret_id: [3; 32],
            range_start: 1_700_000,
            range_width: 1,
            bit_depth: 0,
            event_id_prefix: [0; 32],
            tombstone_node_id: [0; 32],
            node_secret: [9; NODE_SECRET_BYTES],
        }
    }

    fn leaf_fact() -> LocalHistoryNodeSecretFact {
        LocalHistoryNodeSecretFact {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            source_secret_id: [3; 32],
            range_start: 1_700_000,
            range_width: 1,
            bit_depth: TRIE_LEAF_BIT_DEPTH,
            event_id_prefix: [9; 32],
            tombstone_node_id: [0; 32],
            node_secret: [7; NODE_SECRET_BYTES],
        }
    }

    #[test]
    fn roundtrips_minute_node() {
        let bytes = encode_fact(&minute_node_fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), minute_node_fact());
    }

    #[test]
    fn roundtrips_trie_leaf() {
        let bytes = encode_fact(&leaf_fact()).expect("encode");
        assert_eq!(decode_fact(&bytes).expect("decode"), leaf_fact());
    }

    #[test]
    fn rejects_zero_secret_material() {
        let bad = LocalHistoryNodeSecretFact {
            node_secret: [0; NODE_SECRET_BYTES],
            ..minute_node_fact()
        };
        assert!(encode_fact(&bad).is_err());
    }

    #[test]
    fn rejects_unmasked_prefix_on_decode() {
        let mut bytes = encode_fact(&minute_node_fact()).expect("encode");
        // Smuggle non-zero bits into a time-tree node's prefix slot.
        bytes[115] = 0x80;
        assert!(decode_fact(&bytes).is_err());
    }

    #[test]
    fn row_value_roundtrip() {
        let value = encode_row_value(&[5; 32], &minute_node_fact()).expect("row");
        let decoded = decode_row_value(&value).expect("decode row");
        assert_eq!(decoded.local_history_node_secret_id, [5; 32]);
        assert_eq!(decoded.tombstone_node_id, [0; 32]);
        assert_eq!(decoded.node_secret, minute_node_fact().node_secret);
    }
}

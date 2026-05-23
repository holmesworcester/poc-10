//! Fixed-width layout for local history-node secret facts.

use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
use crate::core::wire;

use super::fact::{mask_prefix_to_depth, LocalHistoryNodeSecretFact};

pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = 153;
pub const LOCAL_HISTORY_NODE_SECRET_BYTES: usize =
    1 + 32 + 32 + 32 + 32 + 8 + 8 + 2 + 32 + 32 + XCHACHA20_POLY1305_KEY_BYTES;

pub fn encode_local_history_node_secret(
    fact: &LocalHistoryNodeSecretFact,
) -> Result<Vec<u8>, String> {
    validate_history_node_coordinate(
        fact.range_start,
        fact.range_width,
        fact.bit_depth,
        fact.fact_id_prefix,
    )?;
    if fact.source_secret_id.iter().all(|byte| *byte == 0) {
        return Err("local history node source_secret_id cannot be empty".to_string());
    }
    if fact.owner_endpoint_id.iter().all(|byte| *byte == 0) {
        return Err("local history node owner_endpoint_id cannot be empty".to_string());
    }
    if fact.node_secret.iter().all(|byte| *byte == 0) {
        return Err("local history node secret material cannot be empty".to_string());
    }
    let mut out = vec![0; LOCAL_HISTORY_NODE_SECRET_BYTES];
    wire::put_u8(TYPE_LOCAL_HISTORY_NODE_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.frontier_id);
    out[65..97].copy_from_slice(&fact.owner_endpoint_id);
    out[97..129].copy_from_slice(&fact.source_secret_id);
    wire::put_u64be(fact.range_start, &mut out[129..137]).map_err(wire_err)?;
    wire::put_u64be(fact.range_width, &mut out[137..145]).map_err(wire_err)?;
    wire::put_u16be(fact.bit_depth, &mut out[145..147]).map_err(wire_err)?;
    out[147..179].copy_from_slice(&fact.fact_id_prefix);
    out[179..211].copy_from_slice(&fact.tombstone_node_id);
    out[211..243].copy_from_slice(&fact.node_secret);
    Ok(out)
}

pub fn decode_local_history_node_secret(
    bytes: &[u8],
) -> Result<LocalHistoryNodeSecretFact, String> {
    wire::expect_len(bytes, LOCAL_HISTORY_NODE_SECRET_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_LOCAL_HISTORY_NODE_SECRET {
        return Err("expected local history node secret".to_string());
    }
    let fact = LocalHistoryNodeSecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        frontier_id: bytes[33..65].try_into().unwrap(),
        owner_endpoint_id: bytes[65..97].try_into().unwrap(),
        source_secret_id: bytes[97..129].try_into().unwrap(),
        range_start: wire::take_u64be(&bytes[129..137]).map_err(wire_err)?,
        range_width: wire::take_u64be(&bytes[137..145]).map_err(wire_err)?,
        bit_depth: wire::take_u16be(&bytes[145..147]).map_err(wire_err)?,
        fact_id_prefix: bytes[147..179].try_into().unwrap(),
        tombstone_node_id: bytes[179..211].try_into().unwrap(),
        node_secret: bytes[211..243].try_into().unwrap(),
    };
    encode_local_history_node_secret(&fact)?;
    Ok(fact)
}

pub(crate) fn validate_history_node_coordinate(
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: [u8; 32],
) -> Result<(), String> {
    if range_width == 0 || !range_width.is_power_of_two() {
        return Err(
            "history-node key wrap range_width must be a non-zero power of two".to_string(),
        );
    }
    if !range_start.is_multiple_of(range_width) {
        return Err("history-node key wrap range_start must be aligned to range_width".to_string());
    }
    if bit_depth > 256 {
        return Err("history-node key wrap bit_depth is out of range".to_string());
    }
    if fact_id_prefix != mask_prefix_to_depth(fact_id_prefix, bit_depth) {
        return Err("history-node key wrap fact_id_prefix must be masked to bit_depth".to_string());
    }
    if range_width > 1 && (bit_depth != 0 || fact_id_prefix != [0; 32]) {
        return Err("history-node key wrap time ranges must have empty trie prefix".to_string());
    }
    Ok(())
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

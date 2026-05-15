//! Fixed-width layouts for local frontier-root and history-node secrets.

use super::coordinate::validate_history_node_coordinate;
use super::fact::{LocalHistoryNodeSecretFact, LocalKeySecretFact};
use crate::core::wire;
use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;

pub const TYPE_LOCAL_KEY_SECRET: u8 = 152;
pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = 153;

pub const LOCAL_KEY_SECRET_BYTES: usize = 1 + 32 + 32 + 32 + 8 + 32;
pub const LOCAL_HISTORY_NODE_SECRET_BYTES: usize =
    1 + 32 + 32 + 32 + 32 + 8 + 8 + 2 + 32 + 32 + XCHACHA20_POLY1305_KEY_BYTES;

pub fn encode_local_key_secret(fact: &LocalKeySecretFact) -> Result<Vec<u8>, String> {
    if fact.key_secret.iter().all(|byte| *byte == 0) {
        return Err("local key secret material cannot be empty".to_string());
    }
    let mut out = vec![0; LOCAL_KEY_SECRET_BYTES];
    wire::put_u8(TYPE_LOCAL_KEY_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.frontier_id);
    out[65..97].copy_from_slice(&fact.owner_endpoint_id);
    wire::put_u64be(fact.created_at_ms, &mut out[97..105]).map_err(wire_err)?;
    out[105..137].copy_from_slice(&fact.key_secret);
    Ok(out)
}

pub fn decode_local_key_secret(bytes: &[u8]) -> Result<LocalKeySecretFact, String> {
    wire::expect_len(bytes, LOCAL_KEY_SECRET_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_LOCAL_KEY_SECRET, "local key secret")?;
    let fact = LocalKeySecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        frontier_id: bytes[33..65].try_into().unwrap(),
        owner_endpoint_id: bytes[65..97].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[97..105]).map_err(wire_err)?,
        key_secret: bytes[105..137].try_into().unwrap(),
    };
    encode_local_key_secret(&fact)?;
    Ok(fact)
}

pub fn encode_local_history_node_secret(
    fact: &LocalHistoryNodeSecretFact,
) -> Result<Vec<u8>, String> {
    validate_history_node_coordinate(
        fact.range_start,
        fact.range_width,
        fact.bit_depth,
        fact.event_id_prefix,
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
    out[147..179].copy_from_slice(&fact.event_id_prefix);
    out[179..211].copy_from_slice(&fact.tombstone_node_id);
    out[211..243].copy_from_slice(&fact.node_secret);
    Ok(out)
}

pub fn decode_local_history_node_secret(
    bytes: &[u8],
) -> Result<LocalHistoryNodeSecretFact, String> {
    wire::expect_len(bytes, LOCAL_HISTORY_NODE_SECRET_BYTES).map_err(wire_err)?;
    expect_tag(
        bytes,
        TYPE_LOCAL_HISTORY_NODE_SECRET,
        "local history node secret",
    )?;
    let fact = LocalHistoryNodeSecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        frontier_id: bytes[33..65].try_into().unwrap(),
        owner_endpoint_id: bytes[65..97].try_into().unwrap(),
        source_secret_id: bytes[97..129].try_into().unwrap(),
        range_start: wire::take_u64be(&bytes[129..137]).map_err(wire_err)?,
        range_width: wire::take_u64be(&bytes[137..145]).map_err(wire_err)?,
        bit_depth: wire::take_u16be(&bytes[145..147]).map_err(wire_err)?,
        event_id_prefix: bytes[147..179].try_into().unwrap(),
        tombstone_node_id: bytes[179..211].try_into().unwrap(),
        node_secret: bytes[211..243].try_into().unwrap(),
    };
    encode_local_history_node_secret(&fact)?;
    Ok(fact)
}

fn expect_tag(bytes: &[u8], expected: u8, label: &str) -> Result<(), String> {
    let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {label}"))
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

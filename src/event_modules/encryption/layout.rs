//! Fixed-width layouts for poc-10 encryption facts.

use crate::core::wire;

use super::fact::{
    KeyRequestFact, LocalHistoryNodeSecretFact, LocalKeySecretFact, RecipientKeyFact,
    RemovalFrontierFact,
};

pub const TYPE_RECIPIENT_KEY: u8 = 150;
pub const TYPE_REMOVAL_FRONTIER: u8 = 151;
pub const TYPE_LOCAL_KEY_SECRET: u8 = 152;
pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = 153;
pub const TYPE_KEY_REQUEST: u8 = 154;

pub const RECIPIENT_KEY_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 8;
pub const REMOVAL_FRONTIER_BYTES: usize = 1 + 32 + 32 + 8;
pub const LOCAL_KEY_SECRET_BYTES: usize = 1 + 32 + 32 + 32 + 8 + 32;
pub const LOCAL_HISTORY_NODE_SECRET_BYTES: usize = 1 + 32 + 32 + 32 + 8 + 8 + 1 + 32;
pub const KEY_REQUEST_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 32 + 8;

pub fn encode_recipient_key(fact: &RecipientKeyFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; RECIPIENT_KEY_BYTES];
    wire::put_u8(TYPE_RECIPIENT_KEY, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.endpoint_id);
    out[65..97].copy_from_slice(&fact.recipient_key);
    out[97..129].copy_from_slice(&fact.previous_recipient_key_id);
    wire::put_u64be(fact.created_at_ms, &mut out[129..137]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_recipient_key(bytes: &[u8]) -> Result<RecipientKeyFact, String> {
    wire::expect_len(bytes, RECIPIENT_KEY_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_RECIPIENT_KEY, "recipient key")?;
    Ok(RecipientKeyFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        endpoint_id: bytes[33..65].try_into().unwrap(),
        recipient_key: bytes[65..97].try_into().unwrap(),
        previous_recipient_key_id: bytes[97..129].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[129..137]).map_err(wire_err)?,
    })
}

pub fn encode_removal_frontier(fact: &RemovalFrontierFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; REMOVAL_FRONTIER_BYTES];
    wire::put_u8(TYPE_REMOVAL_FRONTIER, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.owner_endpoint_id);
    wire::put_u64be(fact.created_at_ms, &mut out[65..73]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_removal_frontier(bytes: &[u8]) -> Result<RemovalFrontierFact, String> {
    wire::expect_len(bytes, REMOVAL_FRONTIER_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_REMOVAL_FRONTIER, "removal frontier")?;
    Ok(RemovalFrontierFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        owner_endpoint_id: bytes[33..65].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
    })
}

pub fn encode_local_key_secret(fact: &LocalKeySecretFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; LOCAL_KEY_SECRET_BYTES];
    wire::put_u8(TYPE_LOCAL_KEY_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.frontier_id);
    out[65..97].copy_from_slice(&fact.owner_endpoint_id);
    wire::put_u64be(fact.created_at_ms, &mut out[97..105]).map_err(wire_err)?;
    out[105..137].copy_from_slice(&fact.secret_commitment);
    Ok(out)
}

pub fn decode_local_key_secret(bytes: &[u8]) -> Result<LocalKeySecretFact, String> {
    wire::expect_len(bytes, LOCAL_KEY_SECRET_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_LOCAL_KEY_SECRET, "local key secret")?;
    Ok(LocalKeySecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        frontier_id: bytes[33..65].try_into().unwrap(),
        owner_endpoint_id: bytes[65..97].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[97..105]).map_err(wire_err)?,
        secret_commitment: bytes[105..137].try_into().unwrap(),
    })
}

pub fn encode_local_history_node_secret(
    fact: &LocalHistoryNodeSecretFact,
) -> Result<Vec<u8>, String> {
    if fact.start_minute > fact.end_minute {
        return Err("history node range is inverted".to_string());
    }
    if fact.prefix_bytes > 32 {
        return Err("history node prefix is too long".to_string());
    }
    let mut out = vec![0; LOCAL_HISTORY_NODE_SECRET_BYTES];
    wire::put_u8(TYPE_LOCAL_HISTORY_NODE_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.frontier_id);
    out[65..97].copy_from_slice(&fact.source_secret_id);
    wire::put_u64be(fact.start_minute, &mut out[97..105]).map_err(wire_err)?;
    wire::put_u64be(fact.end_minute, &mut out[105..113]).map_err(wire_err)?;
    out[113] = fact.prefix_bytes;
    out[114..146].copy_from_slice(&fact.leaf_prefix);
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
        source_secret_id: bytes[65..97].try_into().unwrap(),
        start_minute: wire::take_u64be(&bytes[97..105]).map_err(wire_err)?,
        end_minute: wire::take_u64be(&bytes[105..113]).map_err(wire_err)?,
        prefix_bytes: bytes[113],
        leaf_prefix: bytes[114..146].try_into().unwrap(),
    };
    encode_local_history_node_secret(&fact)?;
    Ok(fact)
}

pub fn encode_key_request(fact: &KeyRequestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; KEY_REQUEST_BYTES];
    wire::put_u8(TYPE_KEY_REQUEST, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.requester_endpoint_id);
    out[65..97].copy_from_slice(&fact.responder_endpoint_id);
    out[97..129].copy_from_slice(&fact.frontier_id);
    out[129..161].copy_from_slice(&fact.recipient_key_id);
    wire::put_u64be(fact.created_at_ms, &mut out[161..169]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_key_request(bytes: &[u8]) -> Result<KeyRequestFact, String> {
    wire::expect_len(bytes, KEY_REQUEST_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_KEY_REQUEST, "key request")?;
    Ok(KeyRequestFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        requester_endpoint_id: bytes[33..65].try_into().unwrap(),
        responder_endpoint_id: bytes[65..97].try_into().unwrap(),
        frontier_id: bytes[97..129].try_into().unwrap(),
        recipient_key_id: bytes[129..161].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[161..169]).map_err(wire_err)?,
    })
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

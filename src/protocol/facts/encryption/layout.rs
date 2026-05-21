//! Fixed-width layouts for poc-10 encryption facts.

use crate::core::crypto::{
    self, X25519_PRIVATE_KEY_BYTES, X25519_PUBLIC_KEY_BYTES, XCHACHA20_POLY1305_KEY_BYTES,
    XCHACHA20_POLY1305_NONCE_BYTES,
};
use crate::core::wire;

use super::fact::{
    KeyRequestFact, KeyWrapFact, LocalHistoryNodeSecretFact, LocalKeySecretFact,
    LocalRecipientKeyFact, RecipientKeyFact, RemovalFrontierFact, WrappedSecretKind,
    KEY_WRAP_CIPHERTEXT_BYTES,
};

pub const TYPE_RECIPIENT_KEY: u8 = 150;
pub const TYPE_REMOVAL_FRONTIER: u8 = 151;
pub const TYPE_LOCAL_KEY_SECRET: u8 = 152;
pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = 153;
pub const TYPE_KEY_REQUEST: u8 = 154;
pub const TYPE_KEY_WRAP: u8 = 155;
pub const TYPE_LOCAL_RECIPIENT_KEY: u8 = 156;

pub const RECIPIENT_KEY_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 8;
pub const REMOVAL_FRONTIER_BYTES: usize = 1 + 32 + 32 + 8;
pub const LOCAL_KEY_SECRET_BYTES: usize = 1 + 32 + 32 + 32 + 8 + 32;
pub const LOCAL_HISTORY_NODE_SECRET_BYTES: usize =
    1 + 32 + 32 + 32 + 32 + 8 + 8 + 2 + 32 + 32 + XCHACHA20_POLY1305_KEY_BYTES;
pub const KEY_REQUEST_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 32 + 8;
pub const LOCAL_RECIPIENT_KEY_BYTES: usize =
    1 + 32 + 32 + X25519_PUBLIC_KEY_BYTES + X25519_PRIVATE_KEY_BYTES;
pub const KEY_WRAP_BYTES: usize = 1
    + 32
    + 8
    + 32
    + 32
    + 1
    + 32
    + 32
    + 32
    + 8
    + 8
    + 2
    + 32
    + 32
    + X25519_PUBLIC_KEY_BYTES
    + XCHACHA20_POLY1305_NONCE_BYTES
    + KEY_WRAP_CIPHERTEXT_BYTES;
pub const KEY_WRAP_COORDINATE_KEY_BYTES: usize = 32 + 32 + 32 + 1 + 8 + 8 + 2 + 32;

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

pub fn encode_local_recipient_key(fact: &LocalRecipientKeyFact) -> Result<Vec<u8>, String> {
    validate_local_recipient_key(fact)?;
    let mut out = vec![0; LOCAL_RECIPIENT_KEY_BYTES];
    wire::put_u8(TYPE_LOCAL_RECIPIENT_KEY, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.recipient_key_id);
    out[65..97].copy_from_slice(&fact.recipient_key);
    out[97..129].copy_from_slice(&fact.recipient_secret);
    Ok(out)
}

pub fn decode_local_recipient_key(bytes: &[u8]) -> Result<LocalRecipientKeyFact, String> {
    wire::expect_len(bytes, LOCAL_RECIPIENT_KEY_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_LOCAL_RECIPIENT_KEY, "local recipient key")?;
    let fact = LocalRecipientKeyFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        recipient_key_id: bytes[33..65].try_into().unwrap(),
        recipient_key: bytes[65..97].try_into().unwrap(),
        recipient_secret: bytes[97..129].try_into().unwrap(),
    };
    validate_local_recipient_key(&fact)?;
    Ok(fact)
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
        fact_id_prefix: bytes[147..179].try_into().unwrap(),
        tombstone_node_id: bytes[179..211].try_into().unwrap(),
        node_secret: bytes[211..243].try_into().unwrap(),
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

pub fn encode_key_wrap(fact: &KeyWrapFact) -> Result<Vec<u8>, String> {
    validate_key_wrap(fact)?;
    let mut out = vec![0; KEY_WRAP_BYTES];
    wire::put_u8(TYPE_KEY_WRAP, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    wire::put_u64be(fact.created_at_ms, &mut out[33..41]).map_err(wire_err)?;
    out[41..73].copy_from_slice(&fact.signer_endpoint_id);
    out[73..105].copy_from_slice(&fact.frontier_id);
    out[105] = fact.wrapped_secret_kind.as_u8();
    out[106..138].copy_from_slice(&fact.wrapped_secret_id);
    out[138..170].copy_from_slice(&fact.wrapped_source_secret_id);
    out[170..202].copy_from_slice(&fact.wrapped_tombstone_node_id);
    wire::put_u64be(fact.range_start, &mut out[202..210]).map_err(wire_err)?;
    wire::put_u64be(fact.range_width, &mut out[210..218]).map_err(wire_err)?;
    wire::put_u16be(fact.bit_depth, &mut out[218..220]).map_err(wire_err)?;
    out[220..252].copy_from_slice(&fact.fact_id_prefix);
    out[252..284].copy_from_slice(&fact.recipient_key_id);
    out[284..316].copy_from_slice(&fact.sender_wrap_public_key);
    out[316..340].copy_from_slice(&fact.nonce);
    out[340..388].copy_from_slice(&fact.ciphertext);
    Ok(out)
}

pub fn decode_key_wrap(bytes: &[u8]) -> Result<KeyWrapFact, String> {
    wire::expect_len(bytes, KEY_WRAP_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_KEY_WRAP, "key wrap")?;
    let fact = KeyWrapFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[33..41]).map_err(wire_err)?,
        signer_endpoint_id: bytes[41..73].try_into().unwrap(),
        frontier_id: bytes[73..105].try_into().unwrap(),
        wrapped_secret_kind: WrappedSecretKind::from_u8(bytes[105])?,
        wrapped_secret_id: bytes[106..138].try_into().unwrap(),
        wrapped_source_secret_id: bytes[138..170].try_into().unwrap(),
        wrapped_tombstone_node_id: bytes[170..202].try_into().unwrap(),
        range_start: wire::take_u64be(&bytes[202..210]).map_err(wire_err)?,
        range_width: wire::take_u64be(&bytes[210..218]).map_err(wire_err)?,
        bit_depth: wire::take_u16be(&bytes[218..220]).map_err(wire_err)?,
        fact_id_prefix: bytes[220..252].try_into().unwrap(),
        recipient_key_id: bytes[252..284].try_into().unwrap(),
        sender_wrap_public_key: bytes[284..316].try_into().unwrap(),
        nonce: bytes[316..340].try_into().unwrap(),
        ciphertext: bytes[340..388].try_into().unwrap(),
    };
    validate_key_wrap(&fact)?;
    Ok(fact)
}

pub fn key_wrap_coordinate_key(fact: &KeyWrapFact) -> Result<Vec<u8>, String> {
    validate_key_wrap(fact)?;
    Ok(key_wrap_coordinate_key_parts(
        fact.workspace_id,
        fact.frontier_id,
        fact.recipient_key_id,
        fact.wrapped_secret_kind,
        fact.range_start,
        fact.range_width,
        fact.bit_depth,
        fact.fact_id_prefix,
    ))
}

pub fn key_wrap_coordinate_key_parts(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    recipient_key_id: [u8; 32],
    wrapped_secret_kind: WrappedSecretKind,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: [u8; 32],
) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_WRAP_COORDINATE_KEY_BYTES);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&frontier_id);
    key.extend_from_slice(&recipient_key_id);
    key.push(wrapped_secret_kind.as_u8());
    key.extend_from_slice(&encode_u64(range_start));
    key.extend_from_slice(&encode_u64(range_width));
    key.extend_from_slice(&encode_u16(bit_depth));
    key.extend_from_slice(&fact_id_prefix);
    key
}

pub fn frontier_root_key_wrap_coordinate_key(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    recipient_key_id: [u8; 32],
) -> Vec<u8> {
    key_wrap_coordinate_key_parts(
        workspace_id,
        frontier_id,
        recipient_key_id,
        WrappedSecretKind::FrontierRoot,
        0,
        0,
        0,
        [0; 32],
    )
}

pub fn history_node_key_wrap_coordinate_key(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    recipient_key_id: [u8; 32],
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: [u8; 32],
) -> Result<Vec<u8>, String> {
    validate_history_node_coordinate(range_start, range_width, bit_depth, fact_id_prefix)?;
    Ok(key_wrap_coordinate_key_parts(
        workspace_id,
        frontier_id,
        recipient_key_id,
        WrappedSecretKind::HistoryNode,
        range_start,
        range_width,
        bit_depth,
        fact_id_prefix,
    ))
}

pub fn validate_key_wrap(fact: &KeyWrapFact) -> Result<(), String> {
    for (name, id) in [
        ("key wrap workspace_id", &fact.workspace_id),
        ("key wrap signer_endpoint_id", &fact.signer_endpoint_id),
        ("key wrap frontier_id", &fact.frontier_id),
        ("key wrap wrapped_secret_id", &fact.wrapped_secret_id),
        ("key wrap recipient_key_id", &fact.recipient_key_id),
        (
            "key wrap sender_wrap_public_key",
            &fact.sender_wrap_public_key,
        ),
    ] {
        if id.iter().all(|byte| *byte == 0) {
            return Err(format!("{name} cannot be empty"));
        }
    }
    if fact.nonce.iter().all(|byte| *byte == 0) {
        return Err("key wrap nonce cannot be empty".to_string());
    }

    match fact.wrapped_secret_kind {
        WrappedSecretKind::FrontierRoot => {
            if fact.range_start != 0
                || fact.range_width != 0
                || fact.bit_depth != 0
                || fact.fact_id_prefix != [0; 32]
                || fact.wrapped_source_secret_id != [0; 32]
                || fact.wrapped_tombstone_node_id != [0; 32]
            {
                return Err("frontier root key wrap target coordinate must be empty".to_string());
            }
        }
        WrappedSecretKind::HistoryNode => {
            if fact.wrapped_source_secret_id.iter().all(|byte| *byte == 0) {
                return Err("key wrap wrapped_source_secret_id cannot be empty".to_string());
            }
            validate_history_node_coordinate(
                fact.range_start,
                fact.range_width,
                fact.bit_depth,
                fact.fact_id_prefix,
            )?;
        }
    }
    Ok(())
}

fn validate_local_recipient_key(fact: &LocalRecipientKeyFact) -> Result<(), String> {
    for (name, id) in [
        ("local recipient key workspace_id", &fact.workspace_id),
        (
            "local recipient key recipient_key_id",
            &fact.recipient_key_id,
        ),
        ("local recipient key recipient_key", &fact.recipient_key),
        (
            "local recipient key recipient_secret",
            &fact.recipient_secret,
        ),
    ] {
        if id.iter().all(|byte| *byte == 0) {
            return Err(format!("{name} cannot be empty"));
        }
    }
    if crypto::x25519_public_key(&fact.recipient_secret) != fact.recipient_key {
        return Err("local recipient key secret does not match public key".to_string());
    }
    Ok(())
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

fn validate_history_node_coordinate(
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
    if range_start % range_width != 0 {
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

fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn encode_u16(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

fn mask_prefix_to_depth(mut prefix: [u8; 32], bit_depth: u16) -> [u8; 32] {
    let bit_depth = bit_depth as usize;
    if bit_depth >= 256 {
        return prefix;
    }
    let byte_index = bit_depth / 8;
    let remaining_bits = bit_depth % 8;
    if remaining_bits == 0 {
        prefix[byte_index..].fill(0);
    } else {
        prefix[byte_index] &= 0xff << (8 - remaining_bits);
        prefix[byte_index + 1..].fill(0);
    }
    prefix
}

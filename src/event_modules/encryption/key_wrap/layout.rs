//! Fixed-width layout, coordinate keys, and validation for key-wrap facts.

use super::fact::{KeyWrapFact, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES};
use super::super::local_secret::coordinate::validate_history_node_coordinate;
use crate::core::crypto::{X25519_PUBLIC_KEY_BYTES, XCHACHA20_POLY1305_NONCE_BYTES};
use crate::core::wire;

pub const TYPE_KEY_WRAP: u8 = 155;

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
    out[218..220].copy_from_slice(&fact.bit_depth.to_be_bytes());
    out[220..252].copy_from_slice(&fact.event_id_prefix);
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
        bit_depth: u16::from_be_bytes(bytes[218..220].try_into().unwrap()),
        event_id_prefix: bytes[220..252].try_into().unwrap(),
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
        fact.event_id_prefix,
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
    event_id_prefix: [u8; 32],
) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_WRAP_COORDINATE_KEY_BYTES);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&frontier_id);
    key.extend_from_slice(&recipient_key_id);
    key.push(wrapped_secret_kind.as_u8());
    key.extend_from_slice(&range_start.to_be_bytes());
    key.extend_from_slice(&range_width.to_be_bytes());
    key.extend_from_slice(&bit_depth.to_be_bytes());
    key.extend_from_slice(&event_id_prefix);
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
    event_id_prefix: [u8; 32],
) -> Result<Vec<u8>, String> {
    validate_history_node_coordinate(range_start, range_width, bit_depth, event_id_prefix)?;
    Ok(key_wrap_coordinate_key_parts(
        workspace_id,
        frontier_id,
        recipient_key_id,
        WrappedSecretKind::HistoryNode,
        range_start,
        range_width,
        bit_depth,
        event_id_prefix,
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
                || fact.event_id_prefix != [0; 32]
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
                fact.event_id_prefix,
            )?;
        }
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

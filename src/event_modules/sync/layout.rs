//! Fixed-width layouts for poc-10 sync context facts.

use crate::core::wire;

use super::fact::{EncryptedRootFact, KeyWrapAvailableFact, SharedEventFact, SyncRangeRequestFact};

pub const TYPE_SYNC_RANGE_REQUEST: u8 = 160;
pub const TYPE_ENCRYPTED_ROOT: u8 = 161;
pub const TYPE_SHARED_EVENT: u8 = 162;
pub const TYPE_KEY_WRAP_AVAILABLE: u8 = 163;

pub const SYNC_RANGE_REQUEST_BYTES: usize = 1 + 32 + 32 + 8 + 8;
pub const ENCRYPTED_ROOT_BYTES: usize = 1 + 32 + 32 + 32 + 32;
pub const SHARED_EVENT_BYTES: usize = 1 + 32 + 32;
pub const KEY_WRAP_AVAILABLE_BYTES: usize = 1 + 32 + 32;

pub fn encode_sync_range_request(fact: &SyncRangeRequestFact) -> Result<Vec<u8>, String> {
    if fact.start > fact.end {
        return Err("sync range request is inverted".to_string());
    }
    let mut out = vec![0; SYNC_RANGE_REQUEST_BYTES];
    wire::put_u8(TYPE_SYNC_RANGE_REQUEST, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.connection_id);
    wire::put_u64be(fact.start, &mut out[65..73]).map_err(wire_err)?;
    wire::put_u64be(fact.end, &mut out[73..81]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_sync_range_request(bytes: &[u8]) -> Result<SyncRangeRequestFact, String> {
    wire::expect_len(bytes, SYNC_RANGE_REQUEST_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_SYNC_RANGE_REQUEST, "sync range request")?;
    let fact = SyncRangeRequestFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        connection_id: bytes[33..65].try_into().unwrap(),
        start: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
        end: wire::take_u64be(&bytes[73..81]).map_err(wire_err)?,
    };
    encode_sync_range_request(&fact)?;
    Ok(fact)
}

pub fn encode_encrypted_root(fact: &EncryptedRootFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCRYPTED_ROOT_BYTES];
    wire::put_u8(TYPE_ENCRYPTED_ROOT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.event_id);
    out[65..97].copy_from_slice(&fact.dependency_id);
    out[97..129].copy_from_slice(&fact.key_wrap_id);
    Ok(out)
}

pub fn decode_encrypted_root(bytes: &[u8]) -> Result<EncryptedRootFact, String> {
    wire::expect_len(bytes, ENCRYPTED_ROOT_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_ENCRYPTED_ROOT, "encrypted root")?;
    Ok(EncryptedRootFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        event_id: bytes[33..65].try_into().unwrap(),
        dependency_id: bytes[65..97].try_into().unwrap(),
        key_wrap_id: bytes[97..129].try_into().unwrap(),
    })
}

pub fn encode_shared_event(fact: &SharedEventFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; SHARED_EVENT_BYTES];
    wire::put_u8(TYPE_SHARED_EVENT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.event_id);
    Ok(out)
}

pub fn decode_shared_event(bytes: &[u8]) -> Result<SharedEventFact, String> {
    wire::expect_len(bytes, SHARED_EVENT_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_SHARED_EVENT, "sync shared event")?;
    Ok(SharedEventFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        event_id: bytes[33..65].try_into().unwrap(),
    })
}

pub fn encode_key_wrap_available(fact: &KeyWrapAvailableFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; KEY_WRAP_AVAILABLE_BYTES];
    wire::put_u8(TYPE_KEY_WRAP_AVAILABLE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.key_wrap_id);
    Ok(out)
}

pub fn decode_key_wrap_available(bytes: &[u8]) -> Result<KeyWrapAvailableFact, String> {
    wire::expect_len(bytes, KEY_WRAP_AVAILABLE_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_KEY_WRAP_AVAILABLE, "sync key wrap available")?;
    Ok(KeyWrapAvailableFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        key_wrap_id: bytes[33..65].try_into().unwrap(),
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

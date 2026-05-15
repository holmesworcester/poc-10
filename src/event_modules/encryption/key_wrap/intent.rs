//! Deferred intents for materializing and unwrapping key-wrap facts.

use super::super::recipient_key::fact::{RecipientKeyId, WorkspaceId};
use super::super::wrap_source::context::{WrapSourceKind, WrapSourceSelector};
use crate::core::facts::FactId;
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::wire::{FixedLayout, U16be, U64be};

pub const MATERIALIZE_KEY_WRAPS: &str = "materialize_key_wraps";
pub const UNWRAP_KEY_WRAP: &str = "unwrap_key_wrap";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeKeyWrapsIntent {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FactId,
    pub recipient_key_id: RecipientKeyId,
    pub source_fact_id: FactId,
    pub signer_secret_fact_id: FactId,
    pub source: WrapSourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrapKeyWrapIntent {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FactId,
    pub recipient_key_id: RecipientKeyId,
    pub key_wrap_id: FactId,
    pub local_recipient_key_id: FactId,
}

pub fn materialize_key_wraps_intent(
    recipient_key_id: RecipientKeyId,
    source_fact_id: FactId,
    signer_secret_fact_id: FactId,
    source: WrapSourceSelector,
) -> Intent {
    let input = MaterializeKeyWrapsIntent {
        workspace_id: source.workspace_id,
        frontier_id: source.frontier_id,
        recipient_key_id,
        source_fact_id,
        signer_secret_fact_id,
        source: source.kind,
    };
    Intent::new(
        IntentKind::new(MATERIALIZE_KEY_WRAPS).expect("valid materialize_key_wraps intent kind"),
        IntentExecution::Deferred,
        materialize_key(&input),
        encode_materialize_payload(&input),
    )
}

pub fn decode_materialize_key_wraps_intent(
    intent: &Intent,
) -> Result<MaterializeKeyWrapsIntent, String> {
    if intent.kind.as_str() != MATERIALIZE_KEY_WRAPS
        || intent.execution != IntentExecution::Deferred
    {
        return Err("expected materialize_key_wraps deferred intent".to_string());
    }
    let input = decode_materialize_payload(&intent.payload)?;
    if materialize_key(&input) != intent.key {
        return Err("materialize_key_wraps intent key does not match payload".to_string());
    }
    Ok(input)
}

pub fn unwrap_key_wrap_intent(input: UnwrapKeyWrapIntent) -> Intent {
    Intent::new(
        IntentKind::new(UNWRAP_KEY_WRAP).expect("valid unwrap_key_wrap intent kind"),
        IntentExecution::Deferred,
        unwrap_key(&input),
        encode_unwrap_payload(&input),
    )
}

pub fn decode_unwrap_key_wrap_intent(intent: &Intent) -> Result<UnwrapKeyWrapIntent, String> {
    if intent.kind.as_str() != UNWRAP_KEY_WRAP || intent.execution != IntentExecution::Deferred {
        return Err("expected unwrap_key_wrap deferred intent".to_string());
    }
    let input = decode_unwrap_payload(&intent.payload)?;
    if unwrap_key(&input) != intent.key {
        return Err("unwrap_key_wrap intent key does not match payload".to_string());
    }
    Ok(input)
}

fn materialize_key(input: &MaterializeKeyWrapsIntent) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 32 + 32 + 1 + 8 + 8 + 2 + 32);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.frontier_id);
    key.extend_from_slice(&input.recipient_key_id);
    match input.source {
        WrapSourceKind::FrontierRoot => {
            key.push(1);
            key.extend_from_slice(&[0; 49]);
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            event_id_prefix,
        } => {
            key.push(2);
            key.extend_from_slice(&encode_u64(range_start));
            key.extend_from_slice(&encode_u64(range_width));
            key.extend_from_slice(&encode_u16(bit_depth));
            key.extend_from_slice(&event_id_prefix);
        }
    }
    key
}

fn unwrap_key(input: &UnwrapKeyWrapIntent) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 * 5);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.frontier_id);
    key.extend_from_slice(&input.recipient_key_id);
    key.extend_from_slice(&input.key_wrap_id);
    key.extend_from_slice(&input.local_recipient_key_id);
    key
}

fn encode_materialize_payload(input: &MaterializeKeyWrapsIntent) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 32 + 32 + 32 + 1 + 8 + 8 + 2 + 32);
    out.push(1);
    out.extend_from_slice(&input.workspace_id);
    out.extend_from_slice(&input.frontier_id);
    out.extend_from_slice(&input.recipient_key_id);
    out.extend_from_slice(&input.source_fact_id);
    out.extend_from_slice(&input.signer_secret_fact_id);
    match input.source {
        WrapSourceKind::FrontierRoot => {
            out.push(1);
            out.extend_from_slice(&[0; 50]);
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            event_id_prefix,
        } => {
            out.push(2);
            out.extend_from_slice(&encode_u64(range_start));
            out.extend_from_slice(&encode_u64(range_width));
            out.extend_from_slice(&encode_u16(bit_depth));
            out.extend_from_slice(&event_id_prefix);
        }
    }
    out
}

fn decode_materialize_payload(payload: &[u8]) -> Result<MaterializeKeyWrapsIntent, String> {
    if payload.len() != 212 || payload[0] != 1 {
        return Err("invalid materialize_key_wraps payload".to_string());
    }
    let workspace_id = payload[1..33].try_into().unwrap();
    let frontier_id = payload[33..65].try_into().unwrap();
    let recipient_key_id = payload[65..97].try_into().unwrap();
    let source_fact_id = payload[97..129].try_into().unwrap();
    let signer_secret_fact_id = payload[129..161].try_into().unwrap();
    let source = match payload[161] {
        1 => {
            if payload[162..212].iter().any(|byte| *byte != 0) {
                return Err("invalid materialize_key_wraps root padding".to_string());
            }
            WrapSourceKind::FrontierRoot
        }
        2 => {
            let range_start = decode_u64(&payload[162..170])?;
            let range_width = decode_u64(&payload[170..178])?;
            let bit_depth = decode_u16(&payload[178..180])?;
            if bit_depth > 256 || range_width == 0 || !range_width.is_power_of_two() {
                return Err("invalid materialize_key_wraps history range".to_string());
            }
            WrapSourceKind::HistoryNode {
                range_start,
                range_width,
                bit_depth,
                event_id_prefix: payload[180..212].try_into().unwrap(),
            }
        }
        _ => return Err("invalid materialize_key_wraps source kind".to_string()),
    };
    Ok(MaterializeKeyWrapsIntent {
        workspace_id,
        frontier_id,
        recipient_key_id,
        source_fact_id,
        signer_secret_fact_id,
        source,
    })
}

fn encode_unwrap_payload(input: &UnwrapKeyWrapIntent) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 * 5);
    out.push(1);
    out.extend_from_slice(&input.workspace_id);
    out.extend_from_slice(&input.frontier_id);
    out.extend_from_slice(&input.recipient_key_id);
    out.extend_from_slice(&input.key_wrap_id);
    out.extend_from_slice(&input.local_recipient_key_id);
    out
}

fn decode_unwrap_payload(payload: &[u8]) -> Result<UnwrapKeyWrapIntent, String> {
    if payload.len() != 1 + 32 * 5 || payload[0] != 1 {
        return Err("invalid unwrap_key_wrap payload".to_string());
    }
    Ok(UnwrapKeyWrapIntent {
        workspace_id: payload[1..33].try_into().unwrap(),
        frontier_id: payload[33..65].try_into().unwrap(),
        recipient_key_id: payload[65..97].try_into().unwrap(),
        key_wrap_id: payload[97..129].try_into().unwrap(),
        local_recipient_key_id: payload[129..161].try_into().unwrap(),
    })
}

fn encode_u64(value: u64) -> [u8; 8] {
    let mut buf = [0; 8];
    U64be(value).encode(&mut buf).expect("u64 fixed layout");
    buf
}

fn encode_u16(value: u16) -> [u8; 2] {
    let mut buf = [0; 2];
    U16be(value).encode(&mut buf).expect("u16 fixed layout");
    buf
}

fn decode_u64(bytes: &[u8]) -> Result<u64, String> {
    U64be::decode(bytes)
        .map(|value| value.0)
        .map_err(|err| format!("invalid u64 field: {err:?}"))
}

fn decode_u16(bytes: &[u8]) -> Result<u16, String> {
    U16be::decode(bytes)
        .map(|value| value.0)
        .map_err(|err| format!("invalid u16 field: {err:?}"))
}

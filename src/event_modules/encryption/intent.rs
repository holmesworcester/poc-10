//! Deferred encryption intent layouts.

use crate::core::facts::FactId;
use crate::core::intents::{Intent, IntentExecution, IntentKind};

use super::context::{WrapSourceKind, WrapSourceSelector};
use super::fact::{RecipientKeyId, WorkspaceId};

pub const MATERIALIZE_KEY_WRAPS: &str = "materialize_key_wraps";
pub const PURGE_RETIRED_RECIPIENT_MATERIAL: &str = "purge_retired_recipient_material";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeKeyWrapsIntent {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FactId,
    pub recipient_key_id: RecipientKeyId,
    pub source_fact_id: FactId,
    pub source: WrapSourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeRetiredRecipientMaterialIntent {
    pub workspace_id: WorkspaceId,
    pub recipient_key_id: RecipientKeyId,
}

pub fn materialize_key_wraps_intent(
    recipient_key_id: RecipientKeyId,
    source_fact_id: FactId,
    source: WrapSourceSelector,
) -> Intent {
    let input = MaterializeKeyWrapsIntent {
        workspace_id: source.workspace_id,
        frontier_id: source.frontier_id,
        recipient_key_id,
        source_fact_id,
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

pub fn purge_retired_recipient_material_intent(
    input: PurgeRetiredRecipientMaterialIntent,
) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_RETIRED_RECIPIENT_MATERIAL)
            .expect("valid purge_retired_recipient_material intent kind"),
        IntentExecution::Deferred,
        retired_recipient_key(input.workspace_id, input.recipient_key_id),
        encode_retired_recipient_payload(input.recipient_key_id),
    )
}

pub fn decode_purge_retired_recipient_material_intent(
    intent: &Intent,
) -> Result<PurgeRetiredRecipientMaterialIntent, String> {
    if intent.kind.as_str() != PURGE_RETIRED_RECIPIENT_MATERIAL
        || intent.execution != IntentExecution::Deferred
    {
        return Err("expected purge_retired_recipient_material deferred intent".to_string());
    }
    let workspace_id = decode_workspace_from_retired_key(&intent.key)?;
    let recipient_key_id = decode_recipient_from_retired_key(&intent.key)?;
    if decode_retired_recipient_payload(&intent.payload)? != recipient_key_id {
        return Err("purge_retired_recipient_material key does not match payload".to_string());
    }
    Ok(PurgeRetiredRecipientMaterialIntent {
        workspace_id,
        recipient_key_id,
    })
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
            key.extend_from_slice(&range_start.to_be_bytes());
            key.extend_from_slice(&range_width.to_be_bytes());
            key.extend_from_slice(&bit_depth.to_be_bytes());
            key.extend_from_slice(&event_id_prefix);
        }
    }
    key
}

fn encode_materialize_payload(input: &MaterializeKeyWrapsIntent) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 32 + 32 + 1 + 8 + 8 + 2 + 32);
    out.push(1);
    out.extend_from_slice(&input.workspace_id);
    out.extend_from_slice(&input.frontier_id);
    out.extend_from_slice(&input.recipient_key_id);
    out.extend_from_slice(&input.source_fact_id);
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
            out.extend_from_slice(&range_start.to_be_bytes());
            out.extend_from_slice(&range_width.to_be_bytes());
            out.extend_from_slice(&bit_depth.to_be_bytes());
            out.extend_from_slice(&event_id_prefix);
        }
    }
    out
}

fn decode_materialize_payload(payload: &[u8]) -> Result<MaterializeKeyWrapsIntent, String> {
    if payload.len() != 180 || payload[0] != 1 {
        return Err("invalid materialize_key_wraps payload".to_string());
    }
    let workspace_id = payload[1..33].try_into().unwrap();
    let frontier_id = payload[33..65].try_into().unwrap();
    let recipient_key_id = payload[65..97].try_into().unwrap();
    let source_fact_id = payload[97..129].try_into().unwrap();
    let source = match payload[129] {
        1 => {
            if payload[130..180].iter().any(|byte| *byte != 0) {
                return Err("invalid materialize_key_wraps root padding".to_string());
            }
            WrapSourceKind::FrontierRoot
        }
        2 => {
            let range_start = u64::from_be_bytes(payload[130..138].try_into().unwrap());
            let range_width = u64::from_be_bytes(payload[138..146].try_into().unwrap());
            let bit_depth = u16::from_be_bytes(payload[146..148].try_into().unwrap());
            if bit_depth > 256 || range_width == 0 || !range_width.is_power_of_two() {
                return Err("invalid materialize_key_wraps history range".to_string());
            }
            WrapSourceKind::HistoryNode {
                range_start,
                range_width,
                bit_depth,
                event_id_prefix: payload[148..180].try_into().unwrap(),
            }
        }
        _ => return Err("invalid materialize_key_wraps source kind".to_string()),
    };
    Ok(MaterializeKeyWrapsIntent {
        workspace_id,
        frontier_id,
        recipient_key_id,
        source_fact_id,
        source,
    })
}

fn retired_recipient_key(workspace_id: WorkspaceId, recipient_key_id: RecipientKeyId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&recipient_key_id);
    key
}

fn decode_workspace_from_retired_key(key: &[u8]) -> Result<WorkspaceId, String> {
    if key.len() != 64 {
        return Err("retired recipient key must be workspace id plus recipient key id".to_string());
    }
    Ok(key[0..32].try_into().unwrap())
}

fn decode_recipient_from_retired_key(key: &[u8]) -> Result<RecipientKeyId, String> {
    if key.len() != 64 {
        return Err("retired recipient key must be workspace id plus recipient key id".to_string());
    }
    Ok(key[32..64].try_into().unwrap())
}

fn encode_retired_recipient_payload(recipient_key_id: RecipientKeyId) -> Vec<u8> {
    let mut payload = Vec::with_capacity(33);
    payload.push(1);
    payload.extend_from_slice(&recipient_key_id);
    payload
}

fn decode_retired_recipient_payload(payload: &[u8]) -> Result<RecipientKeyId, String> {
    if payload.len() != 33 || payload[0] != 1 {
        return Err("invalid purge_retired_recipient_material payload".to_string());
    }
    Ok(payload[1..33].try_into().unwrap())
}

//! Deferred intent for purging retired local recipient-key material.

use super::fact::{RecipientKeyId, WorkspaceId};
use crate::core::facts::FactId;
use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub const PURGE_RETIRED_RECIPIENT_MATERIAL: &str = "purge_retired_recipient_material";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeRetiredRecipientMaterialIntent {
    pub workspace_id: WorkspaceId,
    pub recipient_key_id: RecipientKeyId,
    pub local_recipient_key_id: FactId,
}

pub fn purge_retired_recipient_material_intent(
    input: PurgeRetiredRecipientMaterialIntent,
) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_RETIRED_RECIPIENT_MATERIAL)
            .expect("valid purge_retired_recipient_material intent kind"),
        IntentExecution::Deferred,
        retired_recipient_key(
            input.workspace_id,
            input.recipient_key_id,
            input.local_recipient_key_id,
        ),
        encode_retired_recipient_payload(input.recipient_key_id, input.local_recipient_key_id),
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
    let local_recipient_key_id = decode_local_recipient_from_retired_key(&intent.key)?;
    if decode_retired_recipient_payload(&intent.payload)?
        != (recipient_key_id, local_recipient_key_id)
    {
        return Err("purge_retired_recipient_material key does not match payload".to_string());
    }
    Ok(PurgeRetiredRecipientMaterialIntent {
        workspace_id,
        recipient_key_id,
        local_recipient_key_id,
    })
}

fn retired_recipient_key(
    workspace_id: WorkspaceId,
    recipient_key_id: RecipientKeyId,
    local_recipient_key_id: FactId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&recipient_key_id);
    key.extend_from_slice(&local_recipient_key_id);
    key
}

fn decode_workspace_from_retired_key(key: &[u8]) -> Result<WorkspaceId, String> {
    if key.len() != 96 {
        return Err(
            "retired recipient key must be workspace id plus recipient key id plus local key id"
                .to_string(),
        );
    }
    Ok(key[0..32].try_into().unwrap())
}

fn decode_recipient_from_retired_key(key: &[u8]) -> Result<RecipientKeyId, String> {
    if key.len() != 96 {
        return Err(
            "retired recipient key must be workspace id plus recipient key id plus local key id"
                .to_string(),
        );
    }
    Ok(key[32..64].try_into().unwrap())
}

fn decode_local_recipient_from_retired_key(key: &[u8]) -> Result<FactId, String> {
    if key.len() != 96 {
        return Err(
            "retired recipient key must be workspace id plus recipient key id plus local key id"
                .to_string(),
        );
    }
    Ok(key[64..96].try_into().unwrap())
}

fn encode_retired_recipient_payload(
    recipient_key_id: RecipientKeyId,
    local_recipient_key_id: FactId,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(65);
    payload.push(1);
    payload.extend_from_slice(&recipient_key_id);
    payload.extend_from_slice(&local_recipient_key_id);
    payload
}

fn decode_retired_recipient_payload(payload: &[u8]) -> Result<(RecipientKeyId, FactId), String> {
    if payload.len() != 65 || payload[0] != 1 {
        return Err("invalid purge_retired_recipient_material payload".to_string());
    }
    Ok((
        payload[1..33].try_into().unwrap(),
        payload[33..65].try_into().unwrap(),
    ))
}

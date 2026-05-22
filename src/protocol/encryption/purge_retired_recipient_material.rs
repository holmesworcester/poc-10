//! Retired local recipient key material intent and handler.
//!
//! Projection emits this intent after local recipient material is matched with a
//! superseding recipient key. The handler revalidates that relationship and
//! purges the local secret. The intent payload, idempotence key, and constructor
//! live here so the handler is self-contained.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{
    HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind,
};

type FactId = HandlerFactId;

use crate::protocol::encryption::key_wrap::create;

pub const PURGE_RETIRED_RECIPIENT_MATERIAL: &str = "purge_retired_recipient_material";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeRetiredRecipientMaterialIntent {
    pub workspace_id: FactId,
    pub recipient_key_id: FactId,
    pub local_recipient_key_id: FactId,
}

pub fn purge_retired_recipient_material_intent(
    input: PurgeRetiredRecipientMaterialIntent,
) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_RETIRED_RECIPIENT_MATERIAL)
            .expect("valid purge_retired_recipient_material intent kind"),
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
    if intent.kind.as_str() != PURGE_RETIRED_RECIPIENT_MATERIAL {
        return Err("expected purge_retired_recipient_material deferred intent".to_string());
    }
    let key = &intent.key;
    if key.len() != 96 {
        return Err(
            "retired recipient key must be workspace id plus recipient key id plus local key id"
                .to_string(),
        );
    }
    let workspace_id: FactId = key[0..32].try_into().unwrap();
    let recipient_key_id: FactId = key[32..64].try_into().unwrap();
    let local_recipient_key_id: FactId = key[64..96].try_into().unwrap();
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
    workspace_id: FactId,
    recipient_key_id: FactId,
    local_recipient_key_id: FactId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&recipient_key_id);
    key.extend_from_slice(&local_recipient_key_id);
    key
}

fn encode_retired_recipient_payload(
    recipient_key_id: FactId,
    local_recipient_key_id: FactId,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(65);
    payload.push(1);
    payload.extend_from_slice(&recipient_key_id);
    payload.extend_from_slice(&local_recipient_key_id);
    payload
}

fn decode_retired_recipient_payload(payload: &[u8]) -> Result<(FactId, FactId), String> {
    if payload.len() != 65 || payload[0] != 1 {
        return Err("invalid purge_retired_recipient_material payload".to_string());
    }
    Ok((
        payload[1..33].try_into().unwrap(),
        payload[33..65].try_into().unwrap(),
    ))
}

#[derive(Debug, Clone, Default)]
pub struct PurgeRetiredRecipientMaterialHandler;

impl PurgeRetiredRecipientMaterialHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeRetiredRecipientMaterialHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_purge_retired_recipient_material_intent(raw_intent)?;
        Ok(vec![input.local_recipient_key_id])
    }

    fn handle(&self, raw_intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_purge_retired_recipient_material_intent(raw_intent)?;
        let local = context.require_fact(&input.local_recipient_key_id)?;
        create::validate_retired_recipient_material(&input, local)?;
        Ok(PipelineEffects::new().purge_fact(input.local_recipient_key_id))
    }
}

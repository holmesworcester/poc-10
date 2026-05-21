//! Handler and deferred intent layout for message-deletion purges.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::core::intents::{Intent, IntentKind};
use crate::protocol::facts::content::{message::retention, message_deletion};

pub const PURGE_DELETED_MESSAGE: &str = "purge_deleted_message";
pub const PURGE_TARGET_MESSAGE: u8 = 1;
pub const PURGE_REASON_AUTHOR_DELETION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeDeletedMessage {
    pub workspace_id: HandlerFactId,
    pub target_kind: u8,
    pub target_id: HandlerFactId,
    pub reason_kind: u8,
    pub reason_fact_id: HandlerFactId,
}

pub fn purge_deleted_message_intent(input: PurgeDeletedMessage) -> Intent {
    let key = purge_deleted_message_key(
        input.workspace_id,
        input.target_kind,
        input.target_id,
        input.reason_kind,
        input.reason_fact_id,
    );
    Intent::new(
        IntentKind::new(PURGE_DELETED_MESSAGE).expect("valid purge_deleted_message intent kind"),
        key,
        encode_purge_deleted_message_payload(&input),
    )
}

pub fn decode_purge_deleted_message_intent(intent: &Intent) -> Result<PurgeDeletedMessage, String> {
    if intent.kind.as_str() != PURGE_DELETED_MESSAGE {
        return Err("expected purge_deleted_message deferred intent".into());
    }
    let decoded = decode_purge_deleted_message_payload(&intent.payload)?;
    let expected_key = purge_deleted_message_key(
        decoded.workspace_id,
        decoded.target_kind,
        decoded.target_id,
        decoded.reason_kind,
        decoded.reason_fact_id,
    );
    if intent.key != expected_key {
        return Err("purge_deleted_message intent key does not match payload".into());
    }
    Ok(decoded)
}

fn purge_deleted_message_key(
    workspace_id: HandlerFactId,
    target_kind: u8,
    target_id: HandlerFactId,
    reason_kind: u8,
    reason_fact_id: HandlerFactId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(98);
    key.extend_from_slice(&workspace_id);
    key.push(target_kind);
    key.extend_from_slice(&target_id);
    key.push(reason_kind);
    key.extend_from_slice(&reason_fact_id);
    key
}

fn encode_purge_deleted_message_payload(input: &PurgeDeletedMessage) -> Vec<u8> {
    let mut payload = Vec::with_capacity(99);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.push(input.target_kind);
    payload.extend_from_slice(&input.target_id);
    payload.push(input.reason_kind);
    payload.extend_from_slice(&input.reason_fact_id);
    payload
}

fn decode_purge_deleted_message_payload(payload: &[u8]) -> Result<PurgeDeletedMessage, String> {
    if payload.len() != 99 || payload[0] != 1 {
        return Err("invalid purge_deleted_message intent payload".into());
    }
    Ok(PurgeDeletedMessage {
        workspace_id: payload[1..33].try_into().unwrap(),
        target_kind: payload[33],
        target_id: payload[34..66].try_into().unwrap(),
        reason_kind: payload[66],
        reason_fact_id: payload[67..99].try_into().unwrap(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct PurgeDeletedMessageHandler;

impl PurgeDeletedMessageHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeDeletedMessageHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_purge_deleted_message_intent(raw_intent)?;
        Ok(vec![input.target_id, input.reason_fact_id])
    }

    fn handle(&self, raw_intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_purge_deleted_message_intent(raw_intent)?;
        if input.target_kind != PURGE_TARGET_MESSAGE {
            return Err("purge_deleted_message target kind is not supported".into());
        }
        if input.reason_kind != PURGE_REASON_AUTHOR_DELETION {
            return Err("purge_deleted_message reason kind is not supported".into());
        }

        let target = context.require_fact(&input.target_id)?;
        let reason = context.require_fact(&input.reason_fact_id)?;
        let message = retention::decode_message_fact(target)?;
        let deletion = message_deletion::decode_any_fact(reason)?;
        if message.workspace_id != input.workspace_id {
            return Ok(PipelineEffects::new());
        }
        if deletion.workspace_id != input.workspace_id {
            return Ok(PipelineEffects::new());
        }
        if deletion.target_message_id != input.target_id {
            return Ok(PipelineEffects::new());
        }
        if deletion.author_user_id != message.author_user_id {
            return Ok(PipelineEffects::new());
        }

        Ok(PipelineEffects::new().purge_fact(input.target_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_deleted_message_intent_round_trips_fixed_payload() {
        let input = PurgeDeletedMessage {
            workspace_id: [1; 32],
            target_kind: PURGE_TARGET_MESSAGE,
            target_id: [2; 32],
            reason_kind: PURGE_REASON_AUTHOR_DELETION,
            reason_fact_id: [3; 32],
        };
        let intent = purge_deleted_message_intent(input.clone());

        assert_eq!(decode_purge_deleted_message_intent(&intent).unwrap(), input);
        assert_eq!(intent.key.len(), 98);
        assert_eq!(intent.payload.len(), 99);
    }

    #[test]
    fn purge_deleted_message_intent_rejects_key_payload_mismatch() {
        let mut intent = purge_deleted_message_intent(PurgeDeletedMessage {
            workspace_id: [1; 32],
            target_kind: PURGE_TARGET_MESSAGE,
            target_id: [2; 32],
            reason_kind: PURGE_REASON_AUTHOR_DELETION,
            reason_fact_id: [3; 32],
        });
        intent.key[97] ^= 0xff;

        assert!(decode_purge_deleted_message_intent(&intent).is_err());
    }
}

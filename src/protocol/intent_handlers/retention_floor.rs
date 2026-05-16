//! Bounded retention-floor handler.
//!
//! The intent names one disappearing-messages setting fact and one sealed
//! message fact. The handler purges only when the message minute is below the
//! setting's monotonic retire floor.

use crate::core::facts::Fact;
use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::store::Store;
use crate::protocol::fact_modules::{disappearing_messages_setting, sealed_message, signed_fact};

pub const APPLY_RETENTION_FLOOR: &str = "apply_retention_floor";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyRetentionFloor {
    pub workspace_id: HandlerFactId,
    pub setting_id: HandlerFactId,
    pub target_id: HandlerFactId,
}

pub fn apply_retention_floor_intent(input: ApplyRetentionFloor) -> Intent {
    Intent::new(
        IntentKind::new(APPLY_RETENTION_FLOOR).expect("valid apply_retention_floor kind"),
        IntentExecution::Deferred,
        apply_retention_floor_key(&input),
        encode_apply_retention_floor(&input),
    )
}

pub fn decode_apply_retention_floor(intent: &Intent) -> Result<ApplyRetentionFloor, String> {
    if intent.kind.as_str() != APPLY_RETENTION_FLOOR
        || intent.execution != IntentExecution::Deferred
    {
        return Err("expected apply_retention_floor deferred intent".to_string());
    }
    let input = decode_apply_floor_payload(&intent.payload)?;
    if intent.key != apply_retention_floor_key(&input) {
        return Err("apply_retention_floor key does not match payload".to_string());
    }
    Ok(input)
}

fn apply_retention_floor_key(input: &ApplyRetentionFloor) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.setting_id);
    key.extend_from_slice(&input.target_id);
    key
}

fn encode_apply_retention_floor(input: &ApplyRetentionFloor) -> Vec<u8> {
    let mut payload = Vec::with_capacity(97);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.extend_from_slice(&input.setting_id);
    payload.extend_from_slice(&input.target_id);
    payload
}

fn decode_apply_floor_payload(payload: &[u8]) -> Result<ApplyRetentionFloor, String> {
    if payload.len() != 97 || payload[0] != 1 {
        return Err("invalid apply_retention_floor payload".to_string());
    }
    Ok(ApplyRetentionFloor {
        workspace_id: payload[1..33].try_into().unwrap(),
        setting_id: payload[33..65].try_into().unwrap(),
        target_id: payload[65..97].try_into().unwrap(),
    })
}

#[derive(Debug, Clone, Default)]
pub struct RetentionFloorHandler;

impl RetentionFloorHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for RetentionFloorHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == APPLY_RETENTION_FLOOR
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_apply_retention_floor(raw_intent)?;
        Ok(vec![input.setting_id, input.target_id])
    }

    fn handle(
        &self,
        raw_intent: &Intent,
        context: &HandlerContext,
    ) -> Result<HandlerOutput, String> {
        let input = decode_apply_retention_floor(raw_intent)?;
        let setting = disappearing_messages_setting::layout::decode_fact(
            &context.require_fact(&input.setting_id)?.bytes,
        )?;
        let target = context.require_fact(&input.target_id)?;
        let message = decode_sealed_message_fact(target)?;

        if setting.workspace_id != input.workspace_id {
            return Err("apply_retention_floor setting workspace mismatch".to_string());
        }
        if message.workspace_id != input.workspace_id {
            return Err("apply_retention_floor target workspace mismatch".to_string());
        }
        if message.minute >= setting.retire_minute {
            return Err("apply_retention_floor target is not below floor".to_string());
        }
        if let Ok(store) = context.store() {
            delete_message_rows(store, input.target_id, &message)?;
        }

        Ok(HandlerOutput::new().purge_fact(input.target_id))
    }
}

fn decode_sealed_message_fact(
    fact: &Fact,
) -> Result<sealed_message::fact::SealedMessageFact, String> {
    match fact.bytes.first().copied() {
        Some(sealed_message::layout::TYPE_SEALED_MESSAGE) => {
            sealed_message::layout::decode_sealed_message(&fact.bytes)
        }
        Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
            if envelope.inner_type != sealed_message::layout::TYPE_SEALED_MESSAGE {
                return Err("signed fact does not contain a sealed message".to_string());
            }
            sealed_message::layout::decode_sealed_message(&envelope.payload)
        }
        _ => Err("expected sealed message fact".to_string()),
    }
}

fn delete_message_rows(
    store: &Store,
    message_id: [u8; 32],
    message: &sealed_message::fact::SealedMessageFact,
) -> Result<(), String> {
    let key = sealed_message::rows::message_key(message.workspace_id, message_id);
    let tombstone = sealed_message::rows::message_tombstone_row(
        message.workspace_id,
        message_id,
        message.author_user_id,
        message.created_at_ms,
    );
    store
        .write_transaction(|tx| {
            tx.insert_table_rows_in_tx(vec![tombstone])?;
            tx.delete_table_rows_in_tx(sealed_message::rows::MESSAGE_ROWS, vec![key.clone()])?;
            tx.delete_table_rows_in_tx(
                sealed_message::rows::OPENED_MESSAGE_ROWS,
                vec![key.clone()],
            )?;
            tx.delete_table_rows_in_tx(sealed_message::rows::SEALED_MESSAGE_ROWS, vec![key])?;
            Ok(())
        })
        .map_err(|err| format!("delete retired message rows: {err}"))?;
    Ok(())
}

//! Bounded per-message expiry handler.
//!
//! The intent names one sealed message fact and the clock minute that made it
//! due. The handler revalidates the message's embedded expiry stamp before
//! purging the fact.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::schema_dsl::{self, FieldValue};
use crate::protocol::facts::content::sealed_message::retention;

pub const PURGE_EXPIRED_MESSAGE: &str = "purge_expired_message";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeExpiredMessage {
    pub workspace_id: HandlerFactId,
    pub target_id: HandlerFactId,
    pub now_minute: u64,
}

pub fn purge_expired_message_intent(input: PurgeExpiredMessage) -> Intent {
    Intent::new(
        IntentKind::new(PURGE_EXPIRED_MESSAGE).expect("valid purge_expired_message kind"),
        IntentExecution::Deferred,
        purge_expired_message_key(&input),
        encode_purge_expired_message(&input),
    )
}

pub fn decode_purge_expired_message(intent: &Intent) -> Result<PurgeExpiredMessage, String> {
    if intent.kind.as_str() != PURGE_EXPIRED_MESSAGE
        || intent.execution != IntentExecution::Deferred
    {
        return Err("expected purge_expired_message deferred intent".to_string());
    }
    let input = decode_purge_expired_message_payload(&intent.payload)?;
    if intent.key != purge_expired_message_key(&input) {
        return Err("purge_expired_message key does not match payload".to_string());
    }
    Ok(input)
}

fn purge_expired_message_key(input: &PurgeExpiredMessage) -> Vec<u8> {
    let mut key = Vec::with_capacity(72);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.target_id);
    key.extend_from_slice(&input.now_minute.to_be_bytes());
    key
}

fn encode_purge_expired_message(input: &PurgeExpiredMessage) -> Vec<u8> {
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("purge_expired_message_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "workspace_id",
                FieldValue::Bytes(input.workspace_id.to_vec()),
            ),
            ("target_id", FieldValue::Bytes(input.target_id.to_vec())),
            ("now_minute", FieldValue::U64(input.now_minute)),
        ],
    )
    .expect("purge_expired_message payload matches schema")
}

fn decode_purge_expired_message_payload(payload: &[u8]) -> Result<PurgeExpiredMessage, String> {
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("purge_expired_message_payload"),
        payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("purge_expired_message payload version unsupported".to_string());
    }
    Ok(PurgeExpiredMessage {
        workspace_id: payload.bytes_array("workspace_id")?,
        target_id: payload.bytes_array("target_id")?,
        now_minute: payload.u64("now_minute")?,
    })
}

#[derive(Debug, Clone, Default)]
pub struct PurgeExpiredMessageHandler;

impl PurgeExpiredMessageHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeExpiredMessageHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == PURGE_EXPIRED_MESSAGE
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_purge_expired_message(raw_intent)?;
        Ok(vec![input.target_id])
    }

    fn handle(
        &self,
        raw_intent: &Intent,
        context: &HandlerContext,
    ) -> Result<HandlerOutput, String> {
        let input = decode_purge_expired_message(raw_intent)?;
        let target = context.require_fact(&input.target_id)?;
        let message = retention::decode_sealed_message_fact(target)?;
        if message.workspace_id != input.workspace_id {
            return Err("purge_expired_message workspace mismatch".to_string());
        }
        if message.expires_at_minute == u64::MAX {
            return Err("purge_expired_message target has no expiry".to_string());
        }
        if message.expires_at_minute > input.now_minute {
            return Err("purge_expired_message target is not due".to_string());
        }
        if let Ok(store) = context.store() {
            retention::delete_message_projection(
                store,
                input.target_id,
                &message,
                "delete expired message rows",
            )?;
        }
        Ok(HandlerOutput::new().purge_fact(input.target_id))
    }
}

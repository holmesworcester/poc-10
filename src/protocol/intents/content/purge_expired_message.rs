//! Bounded per-message expiry handler.
//!
//! The intent names one message fact and the clock minute that made it
//! due. The handler revalidates the message's embedded expiry stamp before
//! purging the fact.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::core::intents::{Intent, IntentKind};
use crate::protocol::facts::content::message::retention;

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
        purge_expired_message_key(&input),
        encode_purge_expired_message(&input),
    )
}

pub fn decode_purge_expired_message(intent: &Intent) -> Result<PurgeExpiredMessage, String> {
    if intent.kind.as_str() != PURGE_EXPIRED_MESSAGE {
        return Err("expected purge_expired_message deferred intent".into());
    }
    let input = decode_purge_expired_message_payload(&intent.payload)?;
    if intent.key != purge_expired_message_key(&input) {
        return Err("purge_expired_message key does not match payload".into());
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
    let mut payload = Vec::with_capacity(73);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.extend_from_slice(&input.target_id);
    payload.extend_from_slice(&input.now_minute.to_be_bytes());
    payload
}

fn decode_purge_expired_message_payload(payload: &[u8]) -> Result<PurgeExpiredMessage, String> {
    if payload.len() != 73 || payload[0] != 1 {
        return Err("invalid purge_expired_message payload".into());
    }
    Ok(PurgeExpiredMessage {
        workspace_id: payload[1..33].try_into().unwrap(),
        target_id: payload[33..65].try_into().unwrap(),
        now_minute: u64::from_be_bytes(payload[65..73].try_into().unwrap()),
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
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_purge_expired_message(raw_intent)?;
        Ok(vec![input.target_id])
    }

    fn handle(&self, raw_intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_purge_expired_message(raw_intent)?;
        let target = context.require_fact(&input.target_id)?;
        let message = retention::decode_message_fact(target)?;
        if message.workspace_id != input.workspace_id {
            return Err("purge_expired_message workspace mismatch".into());
        }
        if message.expires_at_minute == u64::MAX {
            return Err("purge_expired_message target has no expiry".into());
        }
        if message.expires_at_minute > input.now_minute {
            return Err("purge_expired_message target is not due".into());
        }
        if let Ok(store) = context.store() {
            retention::delete_message_projection(
                store,
                input.target_id,
                &message,
                "delete expired message rows",
            )?;
        }
        Ok(PipelineEffects::new().purge_fact(input.target_id))
    }
}

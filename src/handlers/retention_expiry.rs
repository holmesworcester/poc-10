//! Bounded per-message expiry handler.
//!
//! The intent names one sealed message fact and the clock minute that made it
//! due. The handler revalidates the message's embedded expiry stamp before
//! purging the fact.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::event_modules::sealed_message;

pub const EXPIRE_MESSAGE: &str = "expire_message";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpireMessage {
    pub workspace_id: HandlerFactId,
    pub target_id: HandlerFactId,
    pub now_minute: u64,
}

pub fn expire_message_intent(input: ExpireMessage) -> Intent {
    Intent::new(
        IntentKind::new(EXPIRE_MESSAGE).expect("valid expire_message kind"),
        IntentExecution::Deferred,
        expire_message_key(&input),
        encode_expire_message(&input),
    )
}

pub fn decode_expire_message(intent: &Intent) -> Result<ExpireMessage, String> {
    if intent.kind.as_str() != EXPIRE_MESSAGE || intent.execution != IntentExecution::Deferred {
        return Err("expected expire_message deferred intent".to_string());
    }
    let input = decode_expire_payload(&intent.payload)?;
    if intent.key != expire_message_key(&input) {
        return Err("expire_message key does not match payload".to_string());
    }
    Ok(input)
}

fn expire_message_key(input: &ExpireMessage) -> Vec<u8> {
    let mut key = Vec::with_capacity(72);
    key.extend_from_slice(&input.workspace_id);
    key.extend_from_slice(&input.target_id);
    key.extend_from_slice(&input.now_minute.to_be_bytes());
    key
}

fn encode_expire_message(input: &ExpireMessage) -> Vec<u8> {
    let mut payload = Vec::with_capacity(73);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.extend_from_slice(&input.target_id);
    payload.extend_from_slice(&input.now_minute.to_be_bytes());
    payload
}

fn decode_expire_payload(payload: &[u8]) -> Result<ExpireMessage, String> {
    if payload.len() != 73 || payload[0] != 1 {
        return Err("invalid expire_message payload".to_string());
    }
    Ok(ExpireMessage {
        workspace_id: payload[1..33].try_into().unwrap(),
        target_id: payload[33..65].try_into().unwrap(),
        now_minute: u64::from_be_bytes(payload[65..73].try_into().unwrap()),
    })
}

#[derive(Debug, Clone, Default)]
pub struct RetentionExpiryHandler;

impl RetentionExpiryHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for RetentionExpiryHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == EXPIRE_MESSAGE
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_expire_message(raw_intent)?;
        Ok(vec![input.target_id])
    }

    fn handle(
        &self,
        raw_intent: &Intent,
        context: &HandlerContext,
    ) -> Result<HandlerOutput, String> {
        let input = decode_expire_message(raw_intent)?;
        let message = sealed_message::layout::decode_sealed_message(
            &context.require_fact(&input.target_id)?.bytes,
        )?;
        if message.workspace_id != input.workspace_id {
            return Err("expire_message workspace mismatch".to_string());
        }
        if message.expires_at_minute == u64::MAX {
            return Err("expire_message target has no expiry".to_string());
        }
        if message.expires_at_minute > input.now_minute {
            return Err("expire_message target is not due".to_string());
        }
        Ok(HandlerOutput::new().purge_fact(input.target_id))
    }
}

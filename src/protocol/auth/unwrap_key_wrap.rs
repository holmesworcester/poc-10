//! Accepted key-wrap recovery intent and handler.
//!
//! Acceptance is represented by the queued intent and its declared facts. The
//! handler opens the specific wrap with the specific local recipient material
//! chosen by projection. The intent payload, idempotence key, and constructor
//! live here so the handler is self-contained.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{
    HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind,
};

type FactId = HandlerFactId;

use crate::protocol::auth::key_wrap::author;

pub const UNWRAP_KEY_WRAP: &str = "unwrap_key_wrap";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrapKeyWrapIntent {
    pub workspace_id: FactId,
    pub frontier_id: FactId,
    pub recipient_key_id: FactId,
    pub key_wrap_id: FactId,
    pub local_recipient_key_id: FactId,
}

pub fn unwrap_key_wrap_intent(input: UnwrapKeyWrapIntent) -> Intent {
    Intent::new(
        IntentKind::new(UNWRAP_KEY_WRAP).expect("valid unwrap_key_wrap intent kind"),
        unwrap_key(&input),
        encode_unwrap_payload(&input),
    )
}

pub fn decode_unwrap_key_wrap_intent(intent: &Intent) -> Result<UnwrapKeyWrapIntent, String> {
    if intent.kind.as_str() != UNWRAP_KEY_WRAP {
        return Err("expected unwrap_key_wrap deferred intent".to_string());
    }
    let input = decode_unwrap_payload(&intent.payload)?;
    if unwrap_key(&input) != intent.key {
        return Err("unwrap_key_wrap intent key does not match payload".to_string());
    }
    Ok(input)
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

#[derive(Debug, Clone, Default)]
pub struct UnwrapKeyWrapHandler;

impl UnwrapKeyWrapHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for UnwrapKeyWrapHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_unwrap_key_wrap_intent(raw_intent)?;
        Ok(vec![
            input.key_wrap_id,
            input.local_recipient_key_id,
            input.recipient_key_id,
            input.frontier_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_unwrap_key_wrap_intent(intent)?;
        let key_wrap = context.require_fact(&input.key_wrap_id)?;
        let local_recipient_key = context.require_fact(&input.local_recipient_key_id)?;
        let recipient = context.require_fact(&input.recipient_key_id)?;
        let frontier = context.require_fact(&input.frontier_id)?;
        let secret = author::unwrap_key_wrap_fact(
            &input,
            key_wrap,
            local_recipient_key,
            recipient,
            frontier,
        )?;
        Ok(PipelineEffects::new().fact(secret))
    }
}

//! Send the fact requested by a sync need-id fact.

use crate::core::intents::{
    HandlerContext, HandlerFactId, HandlerOutput, HandlerResult, IntentHandler,
};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::protocol::facts::sync::need_id;
use crate::protocol::intents::transport::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};

pub const SEND_REQUESTED_FACT: &str = "send_requested_fact";

pub type HandlerId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRequestedFact {
    pub need_fact_id: HandlerId,
}

pub fn send_requested_fact_intent(input: SendRequestedFact) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32);
    payload.push(1);
    payload.extend_from_slice(&input.need_fact_id);
    Intent::new(
        IntentKind::new(SEND_REQUESTED_FACT).expect("valid send_requested_fact kind"),
        IntentExecution::Deferred,
        send_requested_fact_key(&input),
        payload,
    )
}

pub fn decode_send_requested_fact(intent: &Intent) -> Result<SendRequestedFact, String> {
    if intent.kind.as_str() != SEND_REQUESTED_FACT {
        return Err("expected send_requested_fact intent".into());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("send_requested_fact intent must be deferred".into());
    }
    if intent.payload.len() != 33 || intent.payload[0] != 1 {
        return Err("send_requested_fact payload is malformed".into());
    }
    let need_fact_id = intent.payload[1..33].try_into().unwrap();
    let input = SendRequestedFact { need_fact_id };
    if intent.key != send_requested_fact_key(&input) {
        return Err("send_requested_fact idempotence key does not match payload".into());
    }
    Ok(input)
}

fn send_requested_fact_key(input: &SendRequestedFact) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:send-requested-fact:v1:");
    hash.update(&input.need_fact_id);
    hash.finalize().as_bytes().to_vec()
}

#[derive(Debug, Clone, Default)]
pub struct SendRequestedFactHandler;

impl SendRequestedFactHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendRequestedFactHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SEND_REQUESTED_FACT
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_requested_fact(intent)?;
        Ok(vec![input.need_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_requested_fact(raw)?;
        let need_fact = context.require_fact(&input.need_fact_id)?;
        let need = need_id::layout::decode_fact(&need_fact.bytes)?;
        let Some(fact) = crate::core::pipeline::persisted_fact(context.store()?, &need.fact_id)?
        else {
            return Ok(HandlerOutput::new());
        };
        if crate::protocol::facts::sync::shared_fact::shareable_fact_for_connection(
            context.store()?,
            need.connection_id,
            need.fact_id,
        )?
        .is_none()
        {
            return Ok(HandlerOutput::new());
        }
        crate::protocol::facts::transport::transit::create::require_sendable_fact(&fact)?;
        Ok(
            HandlerOutput::new().intent(send_facts_on_connection_intent(SendFactsOnConnection {
                connection_id: need.connection_id,
                fact_ids: vec![need.fact_id],
            })),
        )
    }
}

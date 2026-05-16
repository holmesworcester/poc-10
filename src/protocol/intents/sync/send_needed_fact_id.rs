//! Send a sync need-id fact for a peer's advertised missing fact.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::protocol::facts::sync::{have_id, need_id};
use crate::protocol::intents::transport::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};

pub const SEND_NEEDED_FACT_ID: &str = "send_needed_fact_id";

pub type HandlerId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendNeededFactId {
    pub have_fact_id: HandlerId,
}

pub fn send_needed_fact_id_intent(input: SendNeededFactId) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32);
    payload.push(1);
    payload.extend_from_slice(&input.have_fact_id);
    Intent::new(
        IntentKind::new(SEND_NEEDED_FACT_ID).expect("valid send_needed_fact_id kind"),
        IntentExecution::Deferred,
        send_needed_fact_id_key(&input),
        payload,
    )
}

pub fn decode_send_needed_fact_id(intent: &Intent) -> Result<SendNeededFactId, String> {
    if intent.kind.as_str() != SEND_NEEDED_FACT_ID {
        return Err("expected send_needed_fact_id intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("send_needed_fact_id intent must be deferred".to_string());
    }
    if intent.payload.len() != 33 || intent.payload[0] != 1 {
        return Err("send_needed_fact_id payload is malformed".to_string());
    }
    let have_fact_id = intent.payload[1..33].try_into().unwrap();
    let input = SendNeededFactId { have_fact_id };
    if intent.key != send_needed_fact_id_key(&input) {
        return Err("send_needed_fact_id idempotence key does not match payload".to_string());
    }
    Ok(input)
}

fn send_needed_fact_id_key(input: &SendNeededFactId) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:send-need-id:v1:");
    hash.update(&input.have_fact_id);
    hash.finalize().as_bytes().to_vec()
}

#[derive(Debug, Clone, Default)]
pub struct SendNeededFactIdHandler;

impl SendNeededFactIdHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendNeededFactIdHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SEND_NEEDED_FACT_ID
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_needed_fact_id(intent)?;
        Ok(vec![input.have_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_send_needed_fact_id(raw)?;
        let have_fact = context.require_fact(&input.have_fact_id)?;
        let have = have_id::layout::decode_fact(&have_fact.bytes)?;
        if crate::core::wake_loop::persisted_fact(context.store()?, &have.fact_id)?.is_some() {
            return Ok(HandlerOutput::new());
        }
        let need = need_id::fact::SyncNeedIdFact {
            connection_id: have.connection_id,
            fact_id: have.fact_id,
        };
        let need_fact = need_id::create::fact(need, have_fact.timestamp)?;
        Ok(HandlerOutput::new()
            .fact(need_fact.clone())
            .intent(send_facts_on_connection_intent(SendFactsOnConnection {
                connection_id: have.connection_id,
                fact_ids: vec![need_fact.id],
            })))
    }
}

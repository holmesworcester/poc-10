//! Intent handler for sending the fact requested by a need-id.
//!
//! Need-id facts name exact payloads a peer says it is missing. This handler
//! loads the requested fact, checks that the fact is shareable on the
//! connection, rejects private or unsendable payloads, and queues connection
//! work for the fact bytes. Authorization remains in the shareable-fact index.

use crate::core::effects::RuntimeEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::core::intents::{Intent, IntentKind};
use crate::protocol::connection::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};
use crate::protocol::sync::{need_id, shared_fact};

pub const SEND_REQUESTED_FACT: &str = "send_requested_fact";

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::update::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

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
        send_requested_fact_key(&input),
        payload,
    )
}

pub fn decode_send_requested_fact(intent: &Intent) -> Result<SendRequestedFact, String> {
    if intent.kind.as_str() != SEND_REQUESTED_FACT {
        return Err("expected send_requested_fact intent".into());
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
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_requested_fact(intent)?;
        Ok(vec![input.need_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_requested_fact(raw)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        let need_fact = context.require_fact(&input.need_fact_id)?;
        let need = need_id::project::decode::decode_fact(&need_fact.bytes)?;
        let Some(fact) = shared_fact::retained_fact(context.db()?, &need.fact_id)? else {
            return Ok(RuntimeEffects::new());
        };
        if shared_fact::shareable_fact_for_connection(
            context.db()?,
            need.connection_id,
            need.fact_id,
        )?
        .is_none()
        {
            return Ok(RuntimeEffects::new());
        }
        crate::protocol::connection::connection::queries::sendable_fact_body(&fact)?;
        Ok(
            RuntimeEffects::new().intent(send_facts_on_connection_intent(SendFactsOnConnection {
                connection_id: need.connection_id,
                fact_ids: vec![need.fact_id],
            })),
        )
    }
}

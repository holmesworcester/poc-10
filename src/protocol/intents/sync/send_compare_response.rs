//! Send sync compare response facts for one inbound compare fact.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::protocol::intents::transport::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};

pub const SEND_SYNC_COMPARE_RESPONSE: &str = "send_sync_compare_response";

pub type HandlerId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendSyncCompareResponse {
    pub compare_fact_id: HandlerId,
}

pub fn send_sync_compare_response_intent(input: SendSyncCompareResponse) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32);
    payload.push(1);
    payload.extend_from_slice(&input.compare_fact_id);
    Intent::new(
        IntentKind::new(SEND_SYNC_COMPARE_RESPONSE).expect("valid send_sync_compare_response kind"),
        IntentExecution::Deferred,
        send_sync_compare_response_key(&input),
        payload,
    )
}

pub fn decode_send_sync_compare_response(
    intent: &Intent,
) -> Result<SendSyncCompareResponse, String> {
    if intent.kind.as_str() != SEND_SYNC_COMPARE_RESPONSE {
        return Err("expected send_sync_compare_response intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("send_sync_compare_response intent must be deferred".to_string());
    }
    if intent.payload.len() != 33 || intent.payload[0] != 1 {
        return Err("send_sync_compare_response payload is malformed".to_string());
    }
    let compare_fact_id = intent.payload[1..33].try_into().unwrap();
    let input = SendSyncCompareResponse { compare_fact_id };
    if intent.key != send_sync_compare_response_key(&input) {
        return Err(
            "send_sync_compare_response idempotence key does not match payload".to_string(),
        );
    }
    Ok(input)
}

fn send_sync_compare_response_key(input: &SendSyncCompareResponse) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:send-compare-response:v1:");
    hash.update(&input.compare_fact_id);
    hash.finalize().as_bytes().to_vec()
}

#[derive(Debug, Clone, Default)]
pub struct SendSyncCompareResponseHandler;

impl SendSyncCompareResponseHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendSyncCompareResponseHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SEND_SYNC_COMPARE_RESPONSE
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_sync_compare_response(intent)?;
        Ok(vec![input.compare_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_send_sync_compare_response(raw)?;
        let compare_fact = context.require_fact(&input.compare_fact_id)?;
        let compare =
            crate::protocol::facts::sync::compare::layout::decode_fact(&compare_fact.bytes)?;
        let available_facts = match context.store() {
            Ok(store) => crate::core::wake_loop::persisted_facts(store)?,
            Err(_) => context.facts().cloned().collect(),
        };
        let mut output = HandlerOutput::new();
        let response_facts = crate::protocol::facts::sync::compare::create::response_facts(
            compare_fact,
            available_facts.iter(),
        )?;
        let fact_ids = response_facts
            .iter()
            .map(|fact| fact.id)
            .collect::<Vec<_>>();
        for fact in response_facts {
            output = output.fact(fact);
        }
        if !fact_ids.is_empty() {
            output = output.intent(send_facts_on_connection_intent(SendFactsOnConnection {
                connection_id: compare.connection_id,
                fact_ids,
            }));
        }
        Ok(output)
    }
}

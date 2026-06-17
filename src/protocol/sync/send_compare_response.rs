//! Intent handler for responding to one sync compare fact.
//!
//! A compare response is deferred because the available shareable facts and the
//! triggering compare fact are runtime state, not fields of the compare itself.
//! The handler loads the connection-visible fact set, asks compare planning for
//! child compares or exact ids, persists any generated compare facts, and queues
//! connection sends when there is something to send.

use crate::core::effects::RuntimeEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::core::intents::{Intent, IntentKind};
use crate::protocol::connection::send_facts_on_connection::{
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
        send_sync_compare_response_key(&input),
        payload,
    )
}

pub fn decode_send_sync_compare_response(
    intent: &Intent,
) -> Result<SendSyncCompareResponse, String> {
    if intent.kind.as_str() != SEND_SYNC_COMPARE_RESPONSE {
        return Err("expected send_sync_compare_response intent".into());
    }
    if intent.payload.len() != 33 || intent.payload[0] != 1 {
        return Err("send_sync_compare_response payload is malformed".into());
    }
    let compare_fact_id = intent.payload[1..33].try_into().unwrap();
    let input = SendSyncCompareResponse { compare_fact_id };
    if intent.key != send_sync_compare_response_key(&input) {
        return Err("send_sync_compare_response idempotence key does not match payload".into());
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
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_sync_compare_response(intent)?;
        Ok(vec![input.compare_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_sync_compare_response(raw)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        let compare_fact = context.require_fact(&input.compare_fact_id)?;
        let compare =
            crate::protocol::sync::compare::project::decode::decode_fact(&compare_fact.bytes)?;
        let mut output = RuntimeEffects::new();
        let (plan, expanded_send_fact_ids) = if let Ok(store) = context.db() {
            let available_facts =
                crate::protocol::sync::shared_fact::shareable_facts_for_connection(
                    store,
                    compare.connection_id,
                )?;
            let plan = crate::protocol::sync::compare::author::response_plan_with_summaries(
                compare_fact,
                available_facts.iter(),
                |range| {
                    crate::protocol::sync::shared_fact::range_summary_for_connection(
                        store,
                        compare.connection_id,
                        range,
                    )
                },
            )?;
            let expanded =
                crate::protocol::sync::shared_fact::expand_fact_ids_with_context_for_connection(
                    store,
                    compare.connection_id,
                    &plan.send_fact_ids,
                )?;
            (plan, expanded)
        } else {
            let available_facts = context.facts().cloned().collect::<Vec<_>>();
            let plan = crate::protocol::sync::compare::author::response_plan(
                compare_fact,
                available_facts.iter(),
            )?;
            let expanded = plan.send_fact_ids.clone();
            (plan, expanded)
        };
        let mut fact_ids = plan.facts.iter().map(|fact| fact.id).collect::<Vec<_>>();
        fact_ids.extend(expanded_send_fact_ids);
        fact_ids.sort();
        fact_ids.dedup();
        for fact in plan.facts {
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

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
            Ok(store) => crate::protocol::facts::sync::shared_fact::shareable_facts_for_connection(
                store,
                compare.connection_id,
            )?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::handler_dispatch::IntentHandler;
    use crate::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use crate::core::store::Store;
    use crate::core::wake_loop::WakeLoop;
    use crate::protocol::facts::connection;
    use crate::protocol::facts::identity;
    use crate::protocol::facts::sync::compare::fact::{
        RangeSummary, SyncCompareFact, TimestampRange,
    };
    use crate::protocol::facts::sync::compare::layout as sync_compare_layout;
    use crate::protocol::facts::sync::have_id::layout as sync_have_id_layout;
    use crate::protocol::facts::sync::shared_fact::{shareable_fact_row, ShareableFactRow};
    use crate::protocol::intents::transport::send_facts_on_connection;

    #[test]
    fn send_sync_compare_response_intent_roundtrips_and_checks_key() {
        let compare_fact_id = [42; 32];
        let intent = send_sync_compare_response_intent(SendSyncCompareResponse { compare_fact_id });

        let decoded = decode_send_sync_compare_response(&intent).expect("decode response intent");
        assert_eq!(decoded.compare_fact_id, compare_fact_id);
        assert_eq!(intent.execution, IntentExecution::Deferred);

        let mut tampered = intent;
        tampered.key[0] ^= 1;
        let err = decode_send_sync_compare_response(&tampered)
            .expect_err("idempotence key mismatch must fail");
        assert!(err.contains("idempotence key"), "{err}");
    }

    #[test]
    fn send_sync_compare_response_declares_compare_fact_as_exact_input() {
        let compare_fact_id = [43; 32];
        let intent = send_sync_compare_response_intent(SendSyncCompareResponse { compare_fact_id });
        let handler = SendSyncCompareResponseHandler::new();

        assert_eq!(
            handler
                .input_fact_ids(&intent)
                .expect("decode exact inputs"),
            vec![compare_fact_id]
        );
    }

    #[test]
    fn send_sync_compare_response_emits_local_summary_and_have_ids() {
        let compare_fact = sync_compare_fact(true);
        let in_range = fact_fact([50; 32], 1_250);
        let out_of_range = fact_fact([51; 32], 9_999);
        let intent = send_sync_compare_response_intent(SendSyncCompareResponse {
            compare_fact_id: compare_fact.id,
        });
        let handler = SendSyncCompareResponseHandler::new();

        let output = handler
            .handle(
                &intent,
                &HandlerContext::with_facts([
                    compare_fact.clone(),
                    in_range.clone(),
                    out_of_range.clone(),
                ]),
            )
            .expect("respond to compare");

        assert!(output.purged_facts.is_empty());
        assert_eq!(output.facts.len(), 2, "response compare + one have-id");
        assert_eq!(output.intents.len(), 1);
        let send = send_facts_on_connection::decode_send_facts_on_connection(&output.intents[0])
            .expect("decode emitted transport send");
        assert_eq!(send.connection_id, [31; 32]);
        assert_eq!(
            send.fact_ids,
            output.facts.iter().map(|fact| fact.id).collect::<Vec<_>>()
        );
        let response = sync_compare_layout::decode_fact(&output.facts[0].bytes)
            .expect("decode response compare");
        assert_eq!(response.connection_id, [31; 32]);
        assert_eq!(response.range.start, 1_000);
        assert_eq!(response.range.end, 2_000);
        assert_eq!(response.summary.count, 1);
        assert_ne!(response.summary.fingerprint, [0; 32]);
        assert!(!response.response_requested);

        let have =
            sync_have_id_layout::decode_fact(&output.facts[1].bytes).expect("decode have-id");
        assert_eq!(have.connection_id, [31; 32]);
        assert_eq!(have.timestamp, in_range.timestamp);
        assert_eq!(have.fact_id, in_range.id);
    }

    #[test]
    fn send_sync_compare_response_uses_shareable_index_for_store_backed_summary() {
        let workspace_id = [9; 32];
        let compare_fact = sync_compare_fact(true);
        let shared = workspace_fact(workspace_id, 50, 1_250);
        let unshared = workspace_fact(workspace_id, 51, 1_300);
        let intent = send_sync_compare_response_intent(SendSyncCompareResponse {
            compare_fact_id: compare_fact.id,
        });
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        seed_shareable_connection(&store, [31; 32], workspace_id);
        persist_facts(&store, [compare_fact.clone(), shared.clone(), unshared]);
        share_fact(&store, workspace_id, &shared);

        let output = SendSyncCompareResponseHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts([compare_fact]).with_store(&store),
            )
            .expect("respond using share index");

        assert_eq!(output.facts.len(), 2, "response compare + one have-id");
        let have =
            sync_have_id_layout::decode_fact(&output.facts[1].bytes).expect("decode have-id");
        assert_eq!(have.fact_id, shared.id);
    }

    #[test]
    fn send_sync_compare_response_dispatch_consumes_intent_after_emitting_response_facts() {
        let compare_fact = sync_compare_fact(true);
        let workspace_id = [9; 32];
        let in_range = workspace_fact(workspace_id, 50, 1_250);
        let intent = send_sync_compare_response_intent(SendSyncCompareResponse {
            compare_fact_id: compare_fact.id,
        });
        let mut bus = WakeLoop::new();
        bus.submit_fact(compare_fact);
        bus.submit_fact(in_range.clone());
        bus.submit_intent(intent).expect("submit response intent");
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        seed_shareable_connection(&store, [31; 32], workspace_id);
        bus.save(&store)
            .expect("persist facts for response handler");
        share_fact(&store, workspace_id, &in_range);

        let report = bus
            .dispatch_deferred_intents_with_fact_context_and_store(
                &SendSyncCompareResponseHandler::new(),
                &store,
                10,
            )
            .expect("range context emits response facts");

        assert_eq!(report.handled, 1);
        assert_eq!(report.facts, 2);
        assert_eq!(bus.intents().len(), 1);
        assert_eq!(
            bus.intents()[0].kind.as_str(),
            send_facts_on_connection::SEND_FACTS_ON_CONNECTION
        );
    }

    #[test]
    fn send_sync_compare_response_consumes_false_positive_intent_when_response_not_requested() {
        let fact = sync_compare_fact(false);
        let intent = send_sync_compare_response_intent(SendSyncCompareResponse {
            compare_fact_id: fact.id,
        });
        let handler = SendSyncCompareResponseHandler::new();

        let output = handler
            .handle(&intent, &HandlerContext::with_facts([fact]))
            .expect("no response needed");

        assert!(output.facts.is_empty());
        assert!(output.purged_facts.is_empty());
        assert!(output.intents.is_empty());
    }

    fn fact_fact(id: [u8; 32], timestamp: u64) -> Fact {
        Fact {
            id,
            scope: FactScope::Global,
            timestamp,
            bytes: vec![1, 2, 3],
        }
    }

    fn workspace_fact(workspace_id: [u8; 32], seed: u8, timestamp: u64) -> Fact {
        let mut bytes = vec![250, seed];
        bytes.extend_from_slice(&workspace_id);
        Fact::new(
            crate::protocol::matchers::workspace_scope(workspace_id),
            timestamp,
            bytes,
        )
    }

    fn persist_facts(store: &Store, facts: impl IntoIterator<Item = Fact>) {
        let mut bus = WakeLoop::new();
        for fact in facts {
            bus.submit_fact(fact);
        }
        bus.save(store).expect("persist facts");
    }

    fn share_fact(store: &Store, workspace_id: [u8; 32], fact: &Fact) {
        store
            .insert_table_rows(vec![shareable_fact_row(ShareableFactRow {
                workspace_id,
                fact_id: fact.id,
                timestamp_ms: fact.timestamp,
            })])
            .expect("share fact row");
    }

    fn seed_shareable_connection(store: &Store, connection_id: [u8; 32], workspace_id: [u8; 32]) {
        let local_secret = [0x11; 32];
        let signing_secret = [0x12; 32];
        let local_endpoint = crypto::x25519_public_key(&local_secret);
        let remote_endpoint = [0x13; 32];
        let local = identity::endpoint::fact::EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&signing_secret),
            signing_secret,
        };
        let connection = connection::response::fact::ConnectionResponseFact {
            from_endpoint: local_endpoint,
            to_endpoint: remote_endpoint,
            request_id: [0x21; 32],
            invite_secret_fact_id: [0x22; 32],
            initiator_ephemeral_secret_fact_id: [0x23; 32],
            responder_ephemeral_secret_fact_id: [0x24; 32],
            responder_ephemeral_public_key: [0x25; 32],
            handshake_hash: [0x26; 32],
            connection_secret: [0x27; 32],
        };
        let endpoint_shared = identity::endpoint_shared::fact::EndpointSharedFact {
            created_at_ms: 1,
            workspace_id,
            user_authority_fact_id: [0x31; 32],
            endpoint_id: remote_endpoint,
            signing_public_key: [0x32; 32],
            endpoint_role: identity::endpoint_shared::fact::EndpointRole::Device,
            device_name: "remote".to_string(),
        };
        let mut rows = identity::endpoint::rows::endpoint_rows(&local);
        rows.push(
            connection::response::rows::connection_response_row(connection_id, &connection)
                .expect("connection row"),
        );
        rows.push(
            identity::endpoint_shared::rows::endpoint_shared_row([0x33; 32], &endpoint_shared)
                .expect("endpoint shared row"),
        );
        store.insert_table_rows(rows).expect("seed connection");
    }

    fn sync_compare_fact(response_requested: bool) -> Fact {
        let compare = SyncCompareFact {
            connection_id: [31; 32],
            range: TimestampRange {
                start: 1_000,
                end: 2_000,
            },
            summary: RangeSummary {
                count: 7,
                fingerprint: [44; 32],
            },
            response_requested,
        };
        Fact::new(
            FactScope::Global,
            1_111,
            sync_compare_layout::encode_fact(&compare).expect("encode sync compare"),
        )
    }
}

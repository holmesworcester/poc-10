use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::core::intents::{Intent, IntentExecution, IntentKind};
use topo::core::schema_dsl::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::protocol::facts::sync::compare::fact::{RangeSummary, SyncCompareFact, TimestampRange};
use topo::protocol::facts::sync::compare::layout as sync_compare_layout;
use topo::protocol::facts::sync::have_id::fact::SyncHaveIdFact;
use topo::protocol::facts::sync::have_id::layout as sync_have_id_layout;
use topo::protocol::facts::sync::need_id::layout as sync_need_id_layout;
use topo::protocol::intents::sync::record_indexed_fact as index_intent;
use topo::protocol::intents::sync::record_indexed_fact::RecordIndexedFactHandler;
use topo::protocol::intents::sync::send_compare_response as compare_intent;
use topo::protocol::intents::sync::send_compare_response::SendSyncCompareResponseHandler;
use topo::protocol::intents::sync::send_needed_fact_id as need_intent;
use topo::protocol::intents::sync::send_needed_fact_id::SendNeededFactIdHandler;
use topo::protocol::intents::transport::send_facts_on_connection;

#[test]
fn send_needed_fact_id_emits_need_fact_for_missing_fact() {
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("store");
    let have_fact = sync_have_id_fact([4; 32], [8; 32], 777);
    let intent = need_intent::send_needed_fact_id_intent(need_intent::SendNeededFactId {
        have_fact_id: have_fact.id,
    });

    let output = SendNeededFactIdHandler::new()
        .handle(
            &intent,
            &HandlerContext::with_facts([have_fact.clone()]).with_store(&store),
        )
        .expect("send need id");

    assert_eq!(output.facts.len(), 1);
    let need = sync_need_id_layout::decode_fact(&output.facts[0].bytes).expect("need fact");
    assert_eq!(need.connection_id, [4; 32]);
    assert_eq!(need.fact_id, [8; 32]);
    assert_eq!(output.intents.len(), 1);
    let send = send_facts_on_connection::decode_send_facts_on_connection(&output.intents[0])
        .expect("transport send");
    assert_eq!(send.connection_id, [4; 32]);
    assert_eq!(send.fact_ids, vec![output.facts[0].id]);
}

#[test]
fn record_indexed_fact_handler_queues_until_durable_fact_lands() {
    let intent = index_intent::record_indexed_fact_intent(index_intent::RecordIndexedFact {
        fact_id: [7; 32],
        timestamp_ms: 1_234_567,
    });
    let mut bus = WakeLoop::new();
    bus.submit_intent(intent.clone()).expect("submit update");

    let handler = RecordIndexedFactHandler::new();
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect("missing fact is not dispatchable yet");
    assert_eq!(report.handled, 0);
    assert_eq!(bus.intents().len(), 1, "intent must stay queued");

    bus.submit_fact(fact_fact([7; 32], 1_234_567));
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect("durable fact lets handler consume update");
    assert_eq!(report.handled, 1);
    assert!(bus.intents().is_empty());

    let decoded = index_intent::decode_record_indexed_fact(&intent).expect("round trip");
    assert_eq!(decoded.fact_id, [7; 32]);
    assert_eq!(decoded.timestamp_ms, 1_234_567);
}

#[test]
fn record_indexed_fact_rejects_wrong_kind() {
    let mismatched = Intent::new(
        IntentKind::new("send_needed_fact_id").unwrap(),
        IntentExecution::Deferred,
        vec![0],
        vec![0],
    );
    let err = index_intent::decode_record_indexed_fact(&mismatched)
        .expect_err("wrong kind must fail to decode");
    assert!(err.contains("record_indexed_fact"), "{err}");
}

#[test]
fn record_indexed_fact_rejects_timestamp_mismatch() {
    let intent = index_intent::record_indexed_fact_intent(index_intent::RecordIndexedFact {
        fact_id: [12; 32],
        timestamp_ms: 22,
    });
    let handler = RecordIndexedFactHandler::new();
    let err = handler
        .handle(
            &intent,
            &HandlerContext::with_facts([fact_fact([12; 32], 21)]),
        )
        .expect_err("timestamp mismatch must fail");

    assert!(err.contains("timestamp does not match"), "{err}");
}

#[test]
fn send_sync_compare_response_intent_roundtrips_and_checks_key() {
    let compare_fact_id = [42; 32];
    let intent = compare_intent::send_sync_compare_response_intent(
        compare_intent::SendSyncCompareResponse { compare_fact_id },
    );

    let decoded =
        compare_intent::decode_send_sync_compare_response(&intent).expect("decode response intent");
    assert_eq!(decoded.compare_fact_id, compare_fact_id);
    assert_eq!(intent.execution, IntentExecution::Deferred);

    let mut tampered = intent;
    tampered.key[0] ^= 1;
    let err = compare_intent::decode_send_sync_compare_response(&tampered)
        .expect_err("idempotence key mismatch must fail");
    assert!(err.contains("idempotence key"), "{err}");
}

#[test]
fn send_sync_compare_response_declares_compare_fact_as_exact_input() {
    let compare_fact_id = [43; 32];
    let intent = compare_intent::send_sync_compare_response_intent(
        compare_intent::SendSyncCompareResponse { compare_fact_id },
    );
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
    let intent = compare_intent::send_sync_compare_response_intent(
        compare_intent::SendSyncCompareResponse {
            compare_fact_id: compare_fact.id,
        },
    );
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
    let response =
        sync_compare_layout::decode_fact(&output.facts[0].bytes).expect("decode response compare");
    assert_eq!(response.connection_id, [31; 32]);
    assert_eq!(response.range.start, 1_000);
    assert_eq!(response.range.end, 2_000);
    assert_eq!(response.summary.count, 1);
    assert_ne!(response.summary.fingerprint, [0; 32]);
    assert!(!response.response_requested);

    let have = sync_have_id_layout::decode_fact(&output.facts[1].bytes).expect("decode have-id");
    assert_eq!(have.connection_id, [31; 32]);
    assert_eq!(have.timestamp, in_range.timestamp);
    assert_eq!(have.fact_id, in_range.id);
}

#[test]
fn send_sync_compare_response_dispatch_consumes_intent_after_emitting_response_facts() {
    let compare_fact = sync_compare_fact(true);
    let in_range = Fact::new(FactScope::Global, 1_250, b"in-range-fact".to_vec());
    let intent = compare_intent::send_sync_compare_response_intent(
        compare_intent::SendSyncCompareResponse {
            compare_fact_id: compare_fact.id,
        },
    );
    let mut bus = WakeLoop::new();
    bus.submit_fact(compare_fact);
    bus.submit_fact(in_range);
    bus.submit_intent(intent).expect("submit response intent");
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("store");
    bus.save(&store)
        .expect("persist facts for response handler");

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
    let intent = compare_intent::send_sync_compare_response_intent(
        compare_intent::SendSyncCompareResponse {
            compare_fact_id: fact.id,
        },
    );
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

fn sync_have_id_fact(connection_id: [u8; 32], fact_id: [u8; 32], timestamp: u64) -> Fact {
    let have = SyncHaveIdFact {
        connection_id,
        timestamp,
        fact_id,
    };
    Fact::new(
        FactScope::Global,
        timestamp,
        sync_have_id_layout::encode_fact(&have).expect("encode have-id"),
    )
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

use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::core::intents::IntentExecution;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::sync_compare::fact::{RangeSummary, SyncCompareFact, TimestampRange};
use topo::event_modules::sync_compare::layout as sync_compare_layout;
use topo::handlers::handle_sync as sync_intent;
use topo::handlers::handle_sync::HandleSyncHandler;
use topo::handlers::handle_sync::RespondToSyncCompareHandler;
use topo::handlers::sync_index_update as index_intent;
use topo::handlers::sync_index_update::SyncIndexUpdateHandler;

#[test]
fn handle_sync_emits_need_id_for_missing_dependency() {
    let connection_id = [1; 32];
    let event_id = [2; 32];
    let dep_id = [3; 32];
    let intent = sync_intent::process_sync_inbound_intent(sync_intent::ProcessSyncInbound {
        connection_id,
        event_id,
        missing_dep_id: Some(dep_id),
    });
    let handler = HandleSyncHandler::new();
    let context = HandlerContext::with_facts([event_fact(event_id, 55)]);

    let output = handler.handle(&intent, &context).expect("handle inbound");

    assert!(output.facts.is_empty());
    assert!(output.purged_facts.is_empty());
    assert_eq!(output.intents.len(), 1);
    let decoded =
        sync_intent::decode_sync_need_id(&output.intents[0]).expect("decode emitted need_id");
    assert_eq!(decoded.connection_id, connection_id);
    assert_eq!(decoded.needed_id, dep_id);
    assert_eq!(output.intents[0].execution, IntentExecution::Deferred);
}

#[test]
fn handle_sync_no_missing_dep_emits_nothing() {
    let intent = sync_intent::process_sync_inbound_intent(sync_intent::ProcessSyncInbound {
        connection_id: [9; 32],
        event_id: [8; 32],
        missing_dep_id: None,
    });
    let handler = HandleSyncHandler::new();

    let output = handler
        .handle(
            &intent,
            &HandlerContext::with_facts([event_fact([8; 32], 99)]),
        )
        .expect("handle inbound");

    assert!(output.facts.is_empty());
    assert!(output.intents.is_empty());
}

#[test]
fn handle_sync_present_dependency_emits_nothing() {
    let connection_id = [4; 32];
    let event_id = [5; 32];
    let dep_id = [6; 32];
    let intent = sync_intent::process_sync_inbound_intent(sync_intent::ProcessSyncInbound {
        connection_id,
        event_id,
        missing_dep_id: Some(dep_id),
    });
    let handler = HandleSyncHandler::new();

    let output = handler
        .handle(
            &intent,
            &HandlerContext::with_facts([event_fact(event_id, 10), event_fact(dep_id, 9)]),
        )
        .expect("handle inbound");

    assert!(output.facts.is_empty());
    assert!(output.intents.is_empty());
}

#[test]
fn handle_sync_dispatches_through_wake_loop() {
    let connection_id = [4; 32];
    let event_id = [5; 32];
    let dep_id = [6; 32];
    let intent = sync_intent::process_sync_inbound_intent(sync_intent::ProcessSyncInbound {
        connection_id,
        event_id,
        missing_dep_id: Some(dep_id),
    });
    let mut bus = WakeLoop::new();
    bus.submit_fact(event_fact(event_id, 77));
    bus.submit_intent(intent).expect("submit inbound");

    let handler = HandleSyncHandler::new();
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect("dispatch handle_sync");

    assert_eq!(report.handled, 1);
    // One follow-up sync_need_id was recorded; the original inbound was consumed.
    let kinds: Vec<&str> = bus
        .intents()
        .iter()
        .map(|intent| intent.kind.as_str())
        .collect();
    assert_eq!(kinds, vec![sync_intent::SYNC_NEED_ID]);
}

#[test]
fn sync_index_update_handler_queues_until_durable_fact_lands() {
    let intent = index_intent::record_indexed_event_intent(index_intent::RecordIndexedEvent {
        event_id: [7; 32],
        timestamp_ms: 1_234_567,
    });
    let mut bus = WakeLoop::new();
    bus.submit_intent(intent.clone()).expect("submit update");

    let handler = SyncIndexUpdateHandler::new();
    let err = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect_err("missing event fact must stay queued for retry");
    assert!(
        err.contains("missing fact"),
        "unexpected error from sync_index_update handler: {err}"
    );

    // The handler must not consume the intent until its exact event fact is
    // available through the deferred fact context.
    assert_eq!(bus.intents().len(), 1, "intent must stay queued for retry");

    bus.submit_fact(event_fact([7; 32], 1_234_567));
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect("durable event fact lets handler consume update");
    assert_eq!(report.handled, 1);
    assert!(bus.intents().is_empty());

    // Direct decode round-trip catches payload-shape regressions.
    let decoded = index_intent::decode_record_indexed_event(&intent).expect("round trip");
    assert_eq!(decoded.event_id, [7; 32]);
    assert_eq!(decoded.timestamp_ms, 1_234_567);
}

#[test]
fn sync_index_update_rejects_wrong_kind() {
    let mismatched = sync_intent::sync_need_id_intent(sync_intent::SyncNeedId {
        connection_id: [10; 32],
        needed_id: [11; 32],
    });
    let err = index_intent::decode_record_indexed_event(&mismatched)
        .expect_err("wrong kind must fail to decode");
    assert!(err.contains("record_indexed_event"), "{err}");
}

#[test]
fn sync_index_update_rejects_timestamp_mismatch() {
    let intent = index_intent::record_indexed_event_intent(index_intent::RecordIndexedEvent {
        event_id: [12; 32],
        timestamp_ms: 22,
    });
    let handler = SyncIndexUpdateHandler::new();
    let err = handler
        .handle(
            &intent,
            &HandlerContext::with_facts([event_fact([12; 32], 21)]),
        )
        .expect_err("timestamp mismatch must fail");

    assert!(err.contains("timestamp does not match"), "{err}");
}

#[test]
fn respond_to_sync_compare_intent_roundtrips_and_checks_key() {
    let compare_fact_id = [42; 32];
    let intent = sync_intent::respond_to_sync_compare_intent(sync_intent::RespondToSyncCompare {
        compare_fact_id,
    });

    let decoded =
        sync_intent::decode_respond_to_sync_compare(&intent).expect("decode response intent");
    assert_eq!(decoded.compare_fact_id, compare_fact_id);
    assert_eq!(intent.execution, IntentExecution::Deferred);

    let mut tampered = intent;
    tampered.key[0] ^= 1;
    let err = sync_intent::decode_respond_to_sync_compare(&tampered)
        .expect_err("idempotence key mismatch must fail");
    assert!(err.contains("idempotence key"), "{err}");
}

#[test]
fn respond_to_sync_compare_declares_compare_fact_as_exact_input() {
    let compare_fact_id = [43; 32];
    let intent = sync_intent::respond_to_sync_compare_intent(sync_intent::RespondToSyncCompare {
        compare_fact_id,
    });
    let handler = RespondToSyncCompareHandler::new();

    assert_eq!(
        handler
            .input_fact_ids(&intent)
            .expect("decode exact inputs"),
        vec![compare_fact_id]
    );
}

#[test]
fn respond_to_sync_compare_stays_queued_until_range_index_context_exists() {
    let fact = sync_compare_fact(true);
    let intent = sync_intent::respond_to_sync_compare_intent(sync_intent::RespondToSyncCompare {
        compare_fact_id: fact.id,
    });
    let mut bus = WakeLoop::new();
    bus.submit_fact(fact);
    bus.submit_intent(intent).expect("submit response intent");

    let err = bus
        .dispatch_deferred_intents_with_fact_context(&RespondToSyncCompareHandler::new(), 10)
        .expect_err("missing bounded range index must keep intent queued");

    assert_eq!(err, sync_intent::SYNC_COMPARE_RANGE_INDEX_NOT_READY);
    assert_eq!(bus.intents().len(), 1, "intent must remain queued");
}

#[test]
fn respond_to_sync_compare_consumes_false_positive_intent_when_response_not_requested() {
    let fact = sync_compare_fact(false);
    let intent = sync_intent::respond_to_sync_compare_intent(sync_intent::RespondToSyncCompare {
        compare_fact_id: fact.id,
    });
    let handler = RespondToSyncCompareHandler::new();

    let output = handler
        .handle(&intent, &HandlerContext::with_facts([fact]))
        .expect("no response needed");

    assert!(output.facts.is_empty());
    assert!(output.purged_facts.is_empty());
    assert!(output.intents.is_empty());
}

fn event_fact(id: [u8; 32], timestamp: u64) -> Fact {
    Fact {
        id,
        scope: FactScope::Global,
        timestamp,
        bytes: vec![1, 2, 3],
    }
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
        1_500,
        sync_compare_layout::encode_fact(&compare).expect("encode sync compare"),
    )
}

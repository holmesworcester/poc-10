use topo::core::event_bus::EventBus;
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::core::intents::IntentExecution;
use topo::handlers::handle_sync::intent as sync_intent;
use topo::handlers::handle_sync::HandleSyncHandler;
use topo::handlers::sync_index_update::intent as index_intent;
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
    let context = HandlerContext::new();

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
        .handle(&intent, &HandlerContext::new())
        .expect("handle inbound");

    assert!(output.facts.is_empty());
    assert!(output.intents.is_empty());
}

#[test]
fn handle_sync_dispatches_through_event_bus() {
    let connection_id = [4; 32];
    let event_id = [5; 32];
    let dep_id = [6; 32];
    let intent = sync_intent::process_sync_inbound_intent(sync_intent::ProcessSyncInbound {
        connection_id,
        event_id,
        missing_dep_id: Some(dep_id),
    });
    let mut bus = EventBus::new();
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
fn sync_index_update_handler_queues_until_durable_index_lands() {
    let intent = index_intent::record_indexed_event_intent(index_intent::RecordIndexedEvent {
        event_id: [7; 32],
        timestamp_ms: 1_234_567,
    });
    let mut bus = EventBus::new();
    bus.submit_intent(intent.clone()).expect("submit update");

    let handler = SyncIndexUpdateHandler::new();
    let err = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect_err("durable sync index update must stay queued for retry");
    assert!(
        err.contains("not yet wired"),
        "unexpected error from sync_index_update handler: {err}"
    );

    // The handler must not consume the intent: producing an empty
    // `HandlerOutput` on success would silently swallow the index update.
    assert_eq!(bus.intents().len(), 1, "intent must stay queued for retry");

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

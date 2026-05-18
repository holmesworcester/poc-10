use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::core::intents::IntentExecution;
use topo::core::schema_dsl::{
    CORE_SCHEMA_SOURCE, EVENT_MODULES_SCHEMA_SOURCE, HANDLERS_SCHEMA_SOURCE,
};
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::connection_response;
use topo::event_modules::identity_endpoint;
use topo::event_modules::identity_endpoint_shared;
use topo::event_modules::signed_fact;
use topo::event_modules::sync_compare::fact::{RangeSummary, SyncCompareFact, TimestampRange};
use topo::event_modules::sync_compare::layout as sync_compare_layout;
use topo::event_modules::sync_have_id::layout as sync_have_id_layout;
use topo::handlers::handle_sync as sync_intent;
use topo::handlers::handle_sync::HandleSyncHandler;
use topo::handlers::handle_sync::RespondToSyncCompareHandler;
use topo::handlers::sync_index_update as index_intent;
use topo::handlers::sync_index_update::SyncIndexUpdateHandler;
use topo::handlers::transit;

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
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect("missing event fact is not dispatchable yet");
    assert_eq!(report.handled, 0);

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
fn sync_index_update_with_store_waits_until_fact_is_persisted() {
    let fact = Fact::new(FactScope::Global, 88, vec![1, 2, 3]);
    let intent = index_intent::record_indexed_event_intent(index_intent::RecordIndexedEvent {
        event_id: fact.id,
        timestamp_ms: fact.timestamp,
    });
    let store = Store::open_memory_with_schema_sources(&[
        CORE_SCHEMA_SOURCE,
        EVENT_MODULES_SCHEMA_SOURCE,
        HANDLERS_SCHEMA_SOURCE,
    ])
    .expect("store");
    let mut bus = WakeLoop::new();
    bus.submit_fact(fact);
    bus.submit_intent(intent).expect("submit update");

    let handler = SyncIndexUpdateHandler::new();
    let report = bus
        .dispatch_deferred_intents_with_fact_context_and_store(&handler, &store, 10)
        .expect("unpersisted fact keeps update queued");
    assert_eq!(report.handled, 0);
    assert_eq!(bus.intents().len(), 1);

    bus.save(&store).expect("persist fact and update");
    let report = bus
        .dispatch_deferred_intents_with_fact_context_and_store(&handler, &store, 10)
        .expect("persisted fact lets update run");
    assert_eq!(report.handled, 1);
    assert!(bus.intents().is_empty());
}

#[test]
fn sync_index_update_seeds_connection_when_endpoint_membership_arrives() {
    let store = Store::open_memory_with_schema_sources(&[
        CORE_SCHEMA_SOURCE,
        EVENT_MODULES_SCHEMA_SOURCE,
        HANDLERS_SCHEMA_SOURCE,
    ])
    .expect("store");
    let local_secret = [3; 32];
    let local_endpoint = crypto::x25519_public_key(&local_secret);
    let local_signing_secret = [4; 32];
    let remote_endpoint = [5; 32];
    let workspace_id = [6; 32];
    let connection_id = [7; 32];
    let endpoint_shared = identity_endpoint_shared::fact::EndpointSharedFact {
        created_at_ms: 99,
        workspace_id,
        user_authority_event_id: [8; 32],
        endpoint_id: remote_endpoint,
        signing_public_key: [9; 32],
        endpoint_role: identity_endpoint_shared::fact::EndpointRole::Device,
        device_name: "remote".to_string(),
    };
    let endpoint_shared_fact = Fact::new(
        FactScope::Global,
        endpoint_shared.created_at_ms,
        signed_fact::create::sign_payload_bytes(
            endpoint_shared.user_authority_event_id,
            &[10; 32],
            identity_endpoint_shared::layout::encode_fact(&endpoint_shared)
                .expect("encode endpoint_shared"),
        )
        .expect("sign endpoint_shared"),
    );
    let connection = connection_response::fact::ConnectionResponseFact {
        from_endpoint: local_endpoint,
        to_endpoint: remote_endpoint,
        request_id: [11; 32],
        invite_secret_event_id: [12; 32],
        initiator_ephemeral_secret_event_id: [13; 32],
        responder_ephemeral_secret_event_id: [14; 32],
        responder_ephemeral_public_key: [15; 32],
        handshake_hash: [16; 32],
        connection_secret: [17; 32],
    };
    let mut rows = identity_endpoint::rows::endpoint_rows(&identity_endpoint::fact::EndpointFact {
        endpoint: local_endpoint,
        secret: local_secret,
        signing_public_key: crypto::ed25519_public_key(&local_signing_secret),
        signing_secret: local_signing_secret,
    });
    rows.push(
        connection_response::rows::connection_response_row(connection_id, &connection)
            .expect("connection row"),
    );
    rows.push(
        identity_endpoint_shared::rows::endpoint_shared_row(
            endpoint_shared_fact.id,
            &endpoint_shared,
        )
        .expect("endpoint_shared row"),
    );
    store.insert_table_rows(rows).expect("insert rows");

    let output = sync_intent::advertise_indexed_fact_to_connections(&store, &endpoint_shared_fact)
        .expect("advertise endpoint membership");

    assert!(output.intents.iter().any(|intent| {
        sync_intent::decode_seed_sync_connection(intent)
            .is_ok_and(|decoded| decoded.connection_id == connection_id)
    }));
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
fn respond_to_sync_compare_emits_local_summary_and_have_ids() {
    let compare_fact = sync_compare_fact(true);
    let in_range = event_fact([50; 32], 1_250);
    let out_of_range = event_fact([51; 32], 9_999);
    let intent = sync_intent::respond_to_sync_compare_intent(sync_intent::RespondToSyncCompare {
        compare_fact_id: compare_fact.id,
    });
    let handler = RespondToSyncCompareHandler::new();

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
    let send = transit::decode_send_on_connection(&output.intents[0])
        .expect("decode emitted transit send");
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
    assert_eq!(have.event_id, in_range.id);
}

#[test]
fn respond_to_sync_compare_dispatch_consumes_intent_after_emitting_response_facts() {
    let compare_fact = sync_compare_fact(true);
    let in_range = Fact::new(FactScope::Global, 1_250, b"in-range-event".to_vec());
    let intent = sync_intent::respond_to_sync_compare_intent(sync_intent::RespondToSyncCompare {
        compare_fact_id: compare_fact.id,
    });
    let mut bus = WakeLoop::new();
    bus.submit_fact(compare_fact);
    bus.submit_fact(in_range);
    bus.submit_intent(intent).expect("submit response intent");
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("store");
    bus.save(&store)
        .expect("persist facts for response handler");

    let report = bus
        .dispatch_deferred_intents_with_fact_context_and_store(
            &RespondToSyncCompareHandler::new(),
            &store,
            10,
        )
        .expect("range context emits response facts");

    assert_eq!(report.handled, 1);
    assert_eq!(report.facts, 2);
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(
        bus.intents()[0].kind.as_str(),
        transit::TRANSIT_SEND_ON_CONNECTION
    );
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

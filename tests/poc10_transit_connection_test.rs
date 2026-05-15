use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, HandlerOutput, IntentHandler};
use topo::core::intents::IntentKind;
use topo::event_modules::{encryption, signed_fact, sync};
use topo::handlers::{connection, transit};

fn connection_drain_output() -> HandlerOutput {
    HandlerOutput::new().intent(transit::wrap_connection_batch_intent(
        transit::TransitWrapConnectionBatch {
            connection_id: [1; 32],
            sender_endpoint: [2; 32],
            recipient_endpoint: [3; 32],
            connection_secret_id: [4; 32],
            send_item_keys: vec![b"out-key-1".to_vec(), b"out-key-2".to_vec()],
            canonical_events: vec![b"event:a".to_vec(), b"event:b".to_vec()],
        },
    ))
}

fn completed_transit_packaging_output(
    wrap_intent: &topo::core::intents::Intent,
    target_addr: &str,
    opaque_frame: Vec<u8>,
) -> HandlerOutput {
    let batch = transit::decode_wrap_connection_batch(wrap_intent).expect("decode wrap intent");
    HandlerOutput::new().intent(connection::send_frame_intent(
        connection::ConnectionSendFrame {
            target_addr: target_addr.to_string(),
            send_item_keys: batch.send_item_keys,
            frame: opaque_frame,
        },
    ))
}

fn connection_send_success_output(send_intent: &topo::core::intents::Intent) -> HandlerOutput {
    let send = connection::decode_send_frame(send_intent).expect("decode send intent");
    HandlerOutput::new().intent(connection::mark_sent_intent(
        connection::ConnectionMarkSent {
            send_item_keys: send.send_item_keys,
        },
    ))
}

#[test]
fn sync_send_on_connection_names_ordered_fact_bundle() {
    let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
        connection_id: [9; 32],
        fact_ids: vec![[1; 32], [2; 32], [3; 32]],
    });

    assert_eq!(intent.kind.as_str(), transit::TRANSIT_SEND_ON_CONNECTION);
    let decoded = transit::decode_send_on_connection(&intent).unwrap();
    assert_eq!(decoded.connection_id, [9; 32]);
    assert_eq!(decoded.fact_ids, vec![[1; 32], [2; 32], [3; 32]]);
}

#[test]
fn transit_send_guard_refuses_forged_local_fact_reference() {
    let fact = Fact::new(
        FactScope::Local,
        1,
        sync::layout::encode_shared_event(&sync::fact::SharedEventFact {
            workspace_id: [7; 32],
            event_id: [8; 32],
        })
        .expect("encode shared event"),
    );
    let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
        connection_id: [9; 32],
        fact_ids: vec![fact.id],
    });
    let context = HandlerContext::with_facts([fact]);

    let err = transit::TransitSendOnConnectionHandler::new()
        .handle(&intent, &context)
        .expect_err("local facts must never be packaged for transit send");

    assert!(
        err.contains("local fact"),
        "error should identify the sendability failure: {err}"
    );
}

#[test]
fn transit_send_guard_refuses_forged_private_tag_reference() {
    for private_tag in [
        signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET,
        encryption::layout::TYPE_LOCAL_KEY_SECRET,
        encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        encryption::layout::TYPE_LOCAL_RECIPIENT_KEY,
    ] {
        let fact = Fact::new(
            sync::context::workspace_scope([7; 32]),
            1,
            vec![private_tag, 1, 2, 3],
        );
        let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
            connection_id: [9; 32],
            fact_ids: vec![fact.id],
        });
        let context = HandlerContext::with_facts([fact]);

        let err = transit::TransitSendOnConnectionHandler::new()
            .handle(&intent, &context)
            .expect_err("private/local fact tags must never be packaged for transit send");

        assert!(
            err.contains("private/local fact tag"),
            "tag {private_tag} should be rejected before packaging: {err}"
        );
    }
}

#[test]
fn transit_send_guard_accepts_normal_shared_facts() {
    let first = Fact::new(
        sync::context::workspace_scope([7; 32]),
        1,
        sync::layout::encode_shared_event(&sync::fact::SharedEventFact {
            workspace_id: [7; 32],
            event_id: [8; 32],
        })
        .expect("encode shared event"),
    );
    let second = Fact::new(
        sync::context::workspace_scope([7; 32]),
        2,
        sync::layout::encode_key_wrap_available(&sync::fact::KeyWrapAvailableFact {
            workspace_id: [7; 32],
            key_wrap_id: [10; 32],
        })
        .expect("encode key wrap available"),
    );
    let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
        connection_id: [9; 32],
        fact_ids: vec![first.id, second.id],
    });
    let context = HandlerContext::with_facts([first.clone(), second.clone()]);
    let input = transit::decode_send_on_connection(&intent).expect("decode send intent");

    let bytes = transit::sendable_fact_bytes(&input, &context).expect("shared facts are sendable");

    assert_eq!(bytes, vec![first.bytes, second.bytes]);
    let err = transit::TransitSendOnConnectionHandler::new()
        .handle(&intent, &context)
        .expect_err("send_on_connection must not consume work until packaging is live");
    assert!(
        err.contains("no live transit packaging handler"),
        "handler should fail retryably instead of dropping work: {err}"
    );
}

#[test]
fn send_on_connection_handler_failure_keeps_intent_queued() {
    let fact = Fact::new(
        sync::context::workspace_scope([7; 32]),
        1,
        sync::layout::encode_shared_event(&sync::fact::SharedEventFact {
            workspace_id: [7; 32],
            event_id: [8; 32],
        })
        .expect("encode shared event"),
    );
    let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
        connection_id: [9; 32],
        fact_ids: vec![fact.id],
    });
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    bus.submit_intent(intent).expect("queue send work");

    let err = bus
        .dispatch_deferred_intents_with_fact_context(
            &transit::TransitSendOnConnectionHandler::new(),
            10,
        )
        .expect_err("send handler is not live yet");

    assert!(err.contains("no live transit packaging handler"), "{err}");
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(
        bus.intents()[0].kind.as_str(),
        transit::TRANSIT_SEND_ON_CONNECTION
    );
}

#[test]
fn connection_drain_emits_transit_wrap_not_network_send() {
    let output = connection_drain_output();

    assert_eq!(output.facts, Vec::new());
    assert_eq!(output.intents.len(), 1);
    assert_eq!(
        output.intents[0].kind.as_str(),
        transit::TRANSIT_WRAP_CONNECTION_BATCH,
        "connection drain chooses route and pending canonical bytes, then delegates packaging"
    );
    assert_ne!(
        output.intents[0].kind.as_str(),
        connection::CONNECTION_SEND_FRAME,
        "connection drain must not bypass transit packaging"
    );

    let decoded = transit::decode_wrap_connection_batch(&output.intents[0]).unwrap();
    assert_eq!(
        decoded.canonical_events,
        vec![b"event:a".to_vec(), b"event:b".to_vec()]
    );
    assert_eq!(
        decoded.connection_secret_id, [4; 32],
        "transit loads secret material by dependency id instead of receiving it in payload"
    );
}

#[test]
fn transit_packaging_completion_emits_opaque_connection_send_frame() {
    let drain = connection_drain_output();
    let opaque_frame = b"opaque-transit-frame".to_vec();

    let wrapped =
        completed_transit_packaging_output(&drain.intents[0], "127.0.0.1:44000", opaque_frame);

    assert_eq!(wrapped.intents.len(), 1);
    assert_eq!(
        wrapped.intents[0].kind.as_str(),
        connection::CONNECTION_SEND_FRAME
    );
    let send = connection::decode_send_frame(&wrapped.intents[0]).unwrap();
    assert_eq!(send.target_addr, "127.0.0.1:44000");
    assert_eq!(
        send.send_item_keys,
        vec![b"out-key-1".to_vec(), b"out-key-2".to_vec()]
    );
    assert_eq!(send.frame, b"opaque-transit-frame".to_vec());
    assert_ne!(
        send.frame,
        b"event:a".to_vec(),
        "connection transport receives transit frame bytes, not canonical events"
    );
}

#[test]
fn connection_send_ack_marks_only_deferred_send_items() {
    let drain = connection_drain_output();
    let wrapped = completed_transit_packaging_output(
        &drain.intents[0],
        "127.0.0.1:44000",
        b"opaque-transit-frame".to_vec(),
    );

    let sent = connection_send_success_output(&wrapped.intents[0]);

    assert_eq!(sent.intents.len(), 1);
    assert_eq!(
        sent.intents[0].kind.as_str(),
        connection::CONNECTION_MARK_SENT
    );
    let mark = connection::decode_mark_sent(&sent.intents[0]).unwrap();
    assert_eq!(
        mark.send_item_keys,
        vec![b"out-key-1".to_vec(), b"out-key-2".to_vec()]
    );
}

#[test]
fn intent_kind_names_keep_crypto_and_transport_boundaries_separate() {
    for kind in [
        transit::TRANSIT_WRAP_CONNECTION_BATCH,
        transit::TRANSIT_SEND_ON_CONNECTION,
        connection::CONNECTION_SEND_FRAME,
        connection::CONNECTION_MARK_SENT,
    ] {
        IntentKind::new(kind).expect("intent kind is registry-safe");
    }

    assert!(
        transit::TRANSIT_WRAP_CONNECTION_BATCH.starts_with("transit_"),
        "cryptographic packaging belongs to transit handlers"
    );
    assert!(
        connection::CONNECTION_SEND_FRAME.starts_with("connection_"),
        "network send/drain belongs to connection handlers"
    );
}

#[test]
fn idempotence_keys_distinguish_parallel_batches_on_same_route() {
    let first_wrap = transit::wrap_connection_batch_intent(transit::TransitWrapConnectionBatch {
        connection_id: [1; 32],
        sender_endpoint: [2; 32],
        recipient_endpoint: [3; 32],
        connection_secret_id: [4; 32],
        send_item_keys: vec![b"out-key-1".to_vec()],
        canonical_events: vec![b"event:a".to_vec()],
    });
    let first_wrap_duplicate = transit::wrap_connection_batch_intent(
        transit::decode_wrap_connection_batch(&first_wrap).unwrap(),
    );
    let second_wrap = transit::wrap_connection_batch_intent(transit::TransitWrapConnectionBatch {
        connection_id: [1; 32],
        sender_endpoint: [2; 32],
        recipient_endpoint: [3; 32],
        connection_secret_id: [4; 32],
        send_item_keys: vec![b"out-key-2".to_vec()],
        canonical_events: vec![b"event:b".to_vec()],
    });

    assert_eq!(first_wrap.key, first_wrap_duplicate.key);
    assert_ne!(
        first_wrap.key, second_wrap.key,
        "same connection may have multiple pending transit batches"
    );

    let first_send = connection::send_frame_intent(connection::ConnectionSendFrame {
        target_addr: "127.0.0.1:44000".to_string(),
        send_item_keys: vec![b"out-key-1".to_vec()],
        frame: b"frame:a".to_vec(),
    });
    let second_send = connection::send_frame_intent(connection::ConnectionSendFrame {
        target_addr: "127.0.0.1:44000".to_string(),
        send_item_keys: vec![b"out-key-2".to_vec()],
        frame: b"frame:b".to_vec(),
    });
    assert_ne!(
        first_send.key, second_send.key,
        "same address may have multiple pending frames"
    );

    let first_mark = connection::mark_sent_intent(connection::ConnectionMarkSent {
        send_item_keys: vec![b"out-key-1".to_vec()],
    });
    let second_mark = connection::mark_sent_intent(connection::ConnectionMarkSent {
        send_item_keys: vec![b"out-key-2".to_vec()],
    });
    assert_ne!(
        first_mark.key, second_mark.key,
        "send acknowledgements are keyed by represented items"
    );
}

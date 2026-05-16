use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, HandlerOutput, IntentHandler};
use topo::core::intents::IntentKind;
use topo::core::schema_dsl::{
    CORE_SCHEMA_SOURCE, EVENT_MODULES_SCHEMA_SOURCE, HANDLERS_SCHEMA_SOURCE,
};
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::connection_response::fact::ConnectionResponseFact;
use topo::event_modules::connection_response::layout as connection_response_layout;
use topo::event_modules::identity_endpoint::fact::EndpointFact;
use topo::event_modules::identity_endpoint::rows as endpoint_rows;
use topo::event_modules::sync_shared_event::{
    fact::SharedEventFact, layout as shared_event_layout,
};
use topo::event_modules::transit::frame as transit_frame;
use topo::event_modules::{encryption, signed_fact, sync};
use topo::handlers::{connection, network_send, transit};

fn connection_fact() -> (Fact, ConnectionResponseFact) {
    let local_endpoint = local_endpoint();
    let connection = ConnectionResponseFact {
        from_endpoint: local_endpoint.endpoint,
        to_endpoint: [11; 32],
        request_id: [12; 32],
        invite_secret_event_id: [13; 32],
        initiator_ephemeral_secret_event_id: [14; 32],
        responder_ephemeral_secret_event_id: [15; 32],
        responder_ephemeral_public_key: [16; 32],
        handshake_hash: [17; 32],
        connection_secret: [18; 32],
    };
    let fact = Fact::new(
        FactScope::Local,
        1,
        connection_response_layout::encode_fact(&connection).expect("connection response"),
    );
    (fact, connection)
}

fn connection_drain_output() -> HandlerOutput {
    HandlerOutput::new().intent(transit::wrap_connection_batch_intent(
        transit::TransitWrapConnectionBatch {
            connection_id: [1; 32],
            sender_endpoint: [2; 32],
            recipient_endpoint: [3; 32],
            connection_secret_id: [4; 32],
            send_item_keys: transit::TransitIntentBytes::from_bytes([
                b"out-key-1".to_vec(),
                b"out-key-2".to_vec(),
            ]),
            canonical_events: transit::TransitIntentBytes::from_bytes([
                b"event:a".to_vec(),
                b"event:b".to_vec(),
            ]),
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
            send_item_keys: batch.send_item_keys.into_items().collect(),
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
    let (connection_fact, _) = connection_fact();
    let fact = Fact::new(
        FactScope::Local,
        1,
        shared_event_layout::encode_fact(&SharedEventFact {
            workspace_id: [7; 32],
            event_id: [8; 32],
        })
        .expect("encode shared event"),
    );
    let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
        connection_id: connection_fact.id,
        fact_ids: vec![fact.id],
    });
    let context = HandlerContext::with_facts([connection_fact, fact]);

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
    let (connection_fact, _) = connection_fact();
    for private_tag in [
        signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET,
        encryption::layout::TYPE_LOCAL_KEY_SECRET,
        encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        encryption::layout::TYPE_LOCAL_RECIPIENT_KEY,
    ] {
        let fact = Fact::new(
            sync::matchers::workspace_scope([7; 32]),
            1,
            vec![private_tag, 1, 2, 3],
        );
        let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
            connection_id: connection_fact.id,
            fact_ids: vec![fact.id],
        });
        let context = HandlerContext::with_facts([connection_fact.clone(), fact]);

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
    let store = store_with_local_endpoint();
    let (connection_fact, connection) = connection_fact();
    let fact = Fact::new(
        sync::matchers::workspace_scope([7; 32]),
        1,
        shared_event_layout::encode_fact(&SharedEventFact {
            workspace_id: [7; 32],
            event_id: [8; 32],
        })
        .expect("encode shared event"),
    );
    let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
        connection_id: connection_fact.id,
        fact_ids: vec![fact.id],
    });
    let context =
        HandlerContext::with_facts([connection_fact.clone(), fact.clone()]).with_store(&store);

    let output = transit::TransitSendOnConnectionHandler::new()
        .handle(&intent, &context)
        .expect("normal shared fact packages for transit");

    assert_eq!(output.intents.len(), 1);
    let send = network_send::decode_network_send_frame(&output.intents[0]).unwrap();
    assert_eq!(send.routing_key, connection_fact.id);
    let opened = transit_frame::open_connection_frame(&send.frame, &connection.connection_secret)
        .expect("open packaged transit frame");
    assert_eq!(
        opened.facts.into_iter().collect::<Vec<_>>(),
        vec![fact.bytes]
    );
}

#[test]
fn send_on_connection_handler_success_emits_network_send_and_clears_intent() {
    let store = store_with_local_endpoint();
    let (connection_fact, _) = connection_fact();
    let fact = Fact::new(
        sync::matchers::workspace_scope([7; 32]),
        1,
        shared_event_layout::encode_fact(&SharedEventFact {
            workspace_id: [7; 32],
            event_id: [8; 32],
        })
        .expect("encode shared event"),
    );
    let intent = transit::send_on_connection_intent(transit::TransitSendOnConnection {
        connection_id: connection_fact.id,
        fact_ids: vec![fact.id],
    });
    let mut bus = WakeLoop::new();
    bus.submit_fact(connection_fact);
    bus.submit_fact(fact);
    bus.submit_intent(intent).expect("queue send work");

    let report = bus
        .dispatch_deferred_intents_with_fact_context_and_store(
            &transit::TransitSendOnConnectionHandler::new(),
            &store,
            10,
        )
        .expect("dispatch transit send");

    assert_eq!(report.handled, 1);
    assert_eq!(report.intents, 1);
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(
        bus.intents()[0].kind.as_str(),
        network_send::NETWORK_SEND_FRAME
    );
}

fn store_with_local_endpoint() -> Store {
    let store = Store::open_memory_with_schema_sources(&[
        CORE_SCHEMA_SOURCE,
        EVENT_MODULES_SCHEMA_SOURCE,
        HANDLERS_SCHEMA_SOURCE,
    ])
    .expect("store");
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&local_endpoint()))
        .expect("seed local endpoint");
    store
}

fn local_endpoint() -> EndpointFact {
    let secret = [23; 32];
    let signing_secret = [24; 32];
    EndpointFact {
        endpoint: crypto::x25519_public_key(&secret),
        secret,
        signing_public_key: crypto::ed25519_public_key(&signing_secret),
        signing_secret,
    }
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
        decoded.canonical_events.into_items().collect::<Vec<_>>(),
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
        send_item_keys: transit::TransitIntentBytes::from_bytes([b"out-key-1".to_vec()]),
        canonical_events: transit::TransitIntentBytes::from_bytes([b"event:a".to_vec()]),
    });
    let first_wrap_duplicate = transit::wrap_connection_batch_intent(
        transit::decode_wrap_connection_batch(&first_wrap).unwrap(),
    );
    let second_wrap = transit::wrap_connection_batch_intent(transit::TransitWrapConnectionBatch {
        connection_id: [1; 32],
        sender_endpoint: [2; 32],
        recipient_endpoint: [3; 32],
        connection_secret_id: [4; 32],
        send_item_keys: transit::TransitIntentBytes::from_bytes([b"out-key-2".to_vec()]),
        canonical_events: transit::TransitIntentBytes::from_bytes([b"event:b".to_vec()]),
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

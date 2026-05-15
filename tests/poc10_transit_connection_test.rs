use topo::core::handler_dispatch::HandlerOutput;
use topo::core::intents::IntentKind;
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

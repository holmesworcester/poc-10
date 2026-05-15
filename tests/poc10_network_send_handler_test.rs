//! NetworkSendHandler wiring tests.
//!
//! Build a `network_send` intent, drive it through the handler, and assert
//! the per-routing-key idempotence cursor fact is emitted. A second submission
//! of the same frame produces a byte-identical cursor fact (same fact id),
//! demonstrating that duplicate sends collapse.

use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::handlers::network_send::{
    build_cursor_fact, network_send_frame_intent, NetworkSendFrame, NetworkSendHandler,
    NETWORK_SEND_CURSOR_TAG, NETWORK_SEND_FRAME,
};

fn sample_input() -> NetworkSendFrame {
    NetworkSendFrame {
        routing_key: [7u8; 32],
        frame: b"opaque-transit-frame-bytes".to_vec(),
    }
}

#[test]
fn happy_path_advances_cursor_and_returns_success() {
    let input = sample_input();
    let intent = network_send_frame_intent(input.clone());
    assert_eq!(intent.kind.as_str(), NETWORK_SEND_FRAME);

    let handler = NetworkSendHandler::new();
    let output = handler
        .handle(&intent, &HandlerContext::new())
        .expect("network_send must succeed for a well-formed frame");

    assert_eq!(
        output.facts.len(),
        1,
        "handler must emit exactly the cursor fact"
    );
    let cursor = &output.facts[0];
    assert_eq!(
        cursor.bytes.first().copied(),
        Some(NETWORK_SEND_CURSOR_TAG),
        "cursor fact must lead with the cursor tag"
    );
    assert_eq!(
        cursor.bytes.len(),
        1 + 32 + 32,
        "cursor body must be tag || routing_key || frame_digest"
    );
    assert_eq!(&cursor.bytes[1..33], &input.routing_key);
    assert_eq!(cursor, &build_cursor_fact(&input));
    assert!(output.intents.is_empty());
    assert!(output.purged_facts.is_empty());
}

#[test]
fn duplicate_send_collapses_to_same_cursor_fact() {
    let input = sample_input();
    let intent = network_send_frame_intent(input.clone());
    let handler = NetworkSendHandler::new();

    let first = handler
        .handle(&intent, &HandlerContext::new())
        .expect("first send");
    let second = handler
        .handle(&intent, &HandlerContext::new())
        .expect("duplicate send");

    assert_eq!(first.facts.len(), 1);
    assert_eq!(second.facts.len(), 1);

    let a = &first.facts[0];
    let b = &second.facts[0];

    // Byte-identical cursor facts → same fact id. The bus stores the cursor
    // once even if the handler runs twice, so duplicate sends do not advance
    // the cursor twice.
    assert_eq!(a.id, b.id, "duplicate send must not produce a new cursor id");
    assert_eq!(a.bytes, b.bytes);

    // A different frame on the same routing key produces a distinct cursor,
    // confirming the cursor is genuinely keyed on (routing_key, frame).
    let other = network_send_frame_intent(NetworkSendFrame {
        routing_key: input.routing_key,
        frame: b"a-different-frame".to_vec(),
    });
    let third = handler
        .handle(&other, &HandlerContext::new())
        .expect("distinct frame send");
    assert_ne!(third.facts[0].id, a.id);
}

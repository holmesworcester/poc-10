//! NetworkSendHandler wiring tests.
//!
//! The handler is currently a frame-envelope guard: it validates the frame
//! bytes' shape, then returns `TCP_SEND_NOT_WIRED` so the intent stays
//! queued until the transport socket lane lands. These tests pin the
//! envelope-shape behaviour without claiming the handler can deliver bytes.

use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::handlers::network_send::{
    network_send_frame_intent, NetworkSendFrame, NetworkSendHandler, NETWORK_SEND_FRAME,
    TCP_SEND_NOT_WIRED,
};

fn sample_input() -> NetworkSendFrame {
    NetworkSendFrame {
        routing_key: [7u8; 32],
        frame: b"opaque-transit-frame-bytes".to_vec(),
    }
}

#[test]
fn well_formed_frame_passes_envelope_check_and_stops_at_tcp_send() {
    let input = sample_input();
    let intent = network_send_frame_intent(input);
    assert_eq!(intent.kind.as_str(), NETWORK_SEND_FRAME);

    let handler = NetworkSendHandler::new();
    let err = handler
        .handle(&intent, &HandlerContext::new())
        .expect_err("tcp send is not yet wired");
    assert_eq!(err, TCP_SEND_NOT_WIRED);
}

#[test]
fn empty_frame_is_rejected_before_tcp_send_stop() {
    let intent = network_send_frame_intent(NetworkSendFrame {
        routing_key: [1u8; 32],
        frame: Vec::new(),
    });
    let handler = NetworkSendHandler::new();
    let err = handler
        .handle(&intent, &HandlerContext::new())
        .expect_err("empty frame must be rejected before tcp stop");
    assert!(err.contains("empty"), "{err}");
}

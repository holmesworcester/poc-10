//! Receive-transit handler wiring tests.
//!
//! Build synthetic outer transit frames through `event_modules::transit::layout`,
//! feed them to the `ReceiveTransitHandler`, and assert the public envelope is
//! decoded and dispatched while the (not-yet-wired) inner AEAD step keeps the
//! intent queued instead of dropping the frame.

use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::core::wire::{FixedBytes, FixedLayout, FixedSlot};
use topo::event_modules::transit::layout::{
    TransitSmallV1, TRANSIT_LARGE_WIRE_BYTES, TRANSIT_SMALL_WIRE_BYTES,
};
use topo::handlers::receive_transit::{
    receive_transit_frame_intent, ReceiveTransitFrame, ReceiveTransitHandler, INNER_OPEN_NOT_WIRED,
    RECEIVE_TRANSIT_FRAME,
};

fn small_frame_bytes() -> Vec<u8> {
    let frame = TransitSmallV1 {
        sender_endpoint_id: FixedBytes([7u8; 32]),
        receiver_endpoint_id: FixedBytes([8u8; 32]),
        connection_id: FixedBytes([9u8; 32]),
        nonce: FixedBytes([1u8; 24]),
        ciphertext: FixedSlot::new(&[2u8; 32]).expect("small slot"),
    };
    let mut out = vec![0u8; TRANSIT_SMALL_WIRE_BYTES];
    frame.encode(&mut out).expect("encode small frame");
    out
}

// Build a large-class frame's bytes directly on the heap. The
// `TransitLargeV1` struct is ~1 MiB and cannot be constructed as a stack
// literal in debug builds without overflowing the thread stack; here we
// patch the size-class byte of a small frame onto a 1 MiB-sized buffer that
// passes the header peek and outer-length check the driver runs.
fn large_frame_bytes() -> Vec<u8> {
    let small = small_frame_bytes();
    let mut out = vec![0u8; TRANSIT_LARGE_WIRE_BYTES];
    // Copy the public header (tag + version + size class + ids + nonce).
    // Offsets are stable per `event_modules::transit::layout`.
    let header_len = 4 + 1 + 1 + 32 + 32 + 32 + 24;
    out[..header_len].copy_from_slice(&small[..header_len]);
    // Patch the size class byte (offset 4 + 1 = 5).
    out[5] = 1; // TRANSIT_FRAME_SIZE_CLASS_LARGE
                // Leave payload slot zero-padded; FixedSlot decode treats the leading
                // u32 length as 0 and the remaining N bytes as zero-padded payload.
    out
}

#[test]
fn well_formed_small_frame_decodes_and_stops_at_inner_open() {
    let bytes = small_frame_bytes();
    let intent = receive_transit_frame_intent(ReceiveTransitFrame {
        frame: bytes.clone(),
    });

    assert_eq!(intent.kind.as_str(), RECEIVE_TRANSIT_FRAME);

    let handler = ReceiveTransitHandler::new();
    let err = handler
        .handle(&intent, &HandlerContext::new())
        .expect_err("inner AEAD open is not yet wired; intent must stay queued");

    assert_eq!(
        err, INNER_OPEN_NOT_WIRED,
        "well-formed frames pass envelope decode and only stop at inner-open stub: {err}"
    );
}

#[test]
fn well_formed_large_frame_decodes_and_stops_at_inner_open() {
    let bytes = large_frame_bytes();
    let intent = receive_transit_frame_intent(ReceiveTransitFrame { frame: bytes });
    let handler = ReceiveTransitHandler::new();

    let err = handler
        .handle(&intent, &HandlerContext::new())
        .expect_err("large frame must also stop at inner-open stub");

    assert_eq!(err, INNER_OPEN_NOT_WIRED);
}

#[test]
fn malformed_frame_header_is_rejected_before_inner_open() {
    let intent = receive_transit_frame_intent(ReceiveTransitFrame {
        frame: vec![0u8; 32],
    });
    let handler = ReceiveTransitHandler::new();

    let err = handler
        .handle(&intent, &HandlerContext::new())
        .expect_err("frame too short to contain header");

    assert!(
        err.contains("malformed frame header"),
        "malformed frames must be rejected at the envelope, not at the inner-open stub: {err}"
    );
    assert!(!err.contains("connection secret"));
}

#[test]
fn truncated_small_frame_after_valid_header_is_rejected() {
    let mut bytes = small_frame_bytes();
    bytes.truncate(TRANSIT_SMALL_WIRE_BYTES - 1);
    let intent = receive_transit_frame_intent(ReceiveTransitFrame { frame: bytes });

    let err = ReceiveTransitHandler::new()
        .handle(&intent, &HandlerContext::new())
        .expect_err("truncated frame must not reach inner-open stub");

    assert!(
        err.contains("wrong outer length") || err.contains("decode failed"),
        "truncated frames must be rejected at envelope decode: {err}"
    );
}

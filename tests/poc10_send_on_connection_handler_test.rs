//! send_on_connection handler wiring tests.
//!
//! Exercises the real transit packaging path (frame size selection, header
//! construction, deterministic nonce, AEAD encrypt) end-to-end through the
//! `package_transit_frame` helper, plus the handler's queueing behaviour
//! while the connection-secret context is not yet wired through
//! `HandlerContext`.

use topo::core::crypto::xchacha20poly1305_decrypt;
use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::event_modules::transit::layout::{
    peek_frame_header, TRANSIT_FRAME_SIZE_CLASS_SMALL, TRANSIT_HEADER_BYTES,
    TRANSIT_LARGE_PLAINTEXT_BYTES, TRANSIT_SMALL_PLAINTEXT_BYTES, TRANSIT_SMALL_WIRE_BYTES,
};
use topo::handlers::transit::{
    derive_transit_nonce, package_transit_frame, pick_size_class, send_on_connection_intent,
    transit_network_send_intent, TransitFrameSizeClass, TransitSendOnConnection,
    TransitSendOnConnectionHandler, INNER_PAYLOAD_VERSION, SECRET_CONTEXT_NOT_WIRED,
    TRANSIT_AEAD_DOMAIN, TRANSIT_NETWORK_SEND,
};

const CONNECTION_ID: [u8; 32] = [9u8; 32];
const SENDER_ENDPOINT: [u8; 32] = [7u8; 32];
const RECEIVER_ENDPOINT: [u8; 32] = [8u8; 32];

/// A sendable fact: the first byte must not match any known private/local
/// fact tag. Pick a tag byte well outside the local-secret range.
fn sendable_fact_bytes(marker: u8) -> Vec<u8> {
    let mut bytes = vec![0xA0u8];
    bytes.push(marker);
    bytes.extend_from_slice(&[marker; 8]);
    bytes
}

#[test]
fn small_frame_packaging_round_trips_through_layout_decode() {
    let secret = [0x11u8; 32];
    let fact_one = sendable_fact_bytes(1);
    let fact_two = sendable_fact_bytes(2);

    // Pack the inner payload the same way the driver does.
    let mut inner = Vec::new();
    inner.push(INNER_PAYLOAD_VERSION);
    inner.extend_from_slice(&2u32.to_be_bytes());
    for fact in [&fact_one, &fact_two] {
        inner.extend_from_slice(&(fact.len() as u32).to_be_bytes());
        inner.extend_from_slice(fact);
    }

    let (class, frame_bytes) = package_transit_frame(
        &secret,
        &SENDER_ENDPOINT,
        &RECEIVER_ENDPOINT,
        &CONNECTION_ID,
        &inner,
    )
    .expect("package small frame");

    assert_eq!(class, TransitFrameSizeClass::Small);
    assert_eq!(frame_bytes.len(), TRANSIT_SMALL_WIRE_BYTES);

    // Public header round-trips through the layout peeker. We use
    // `peek_frame_header` rather than `TransitSmallV1::decode` so the test
    // never moves the ~4 KiB frame struct through the stack in debug builds.
    let header = peek_frame_header(&frame_bytes).expect("peek header");
    assert_eq!(header.size_class, TRANSIT_FRAME_SIZE_CLASS_SMALL);
    assert_eq!(header.sender_endpoint_id.0, SENDER_ENDPOINT);
    assert_eq!(header.receiver_endpoint_id.0, RECEIVER_ENDPOINT);
    assert_eq!(header.connection_id.0, CONNECTION_ID);

    // The nonce on the wire matches the deterministic derivation.
    let expected_nonce = derive_transit_nonce(&CONNECTION_ID, &inner);
    assert_eq!(header.nonce.0, expected_nonce);

    // Manually unpack the FixedSlot ciphertext (u32 BE length prefix + padded
    // bytes) and decrypt with the same AAD the encoder built.
    let slot = &frame_bytes[TRANSIT_HEADER_BYTES..];
    let ct_len = u32::from_be_bytes(slot[..4].try_into().unwrap()) as usize;
    let ciphertext_bytes = &slot[4..4 + ct_len];

    // Reproduce the same AAD the encoder used and AEAD-open the ciphertext.
    let mut aad = Vec::new();
    aad.extend_from_slice(TRANSIT_AEAD_DOMAIN);
    aad.push(TRANSIT_FRAME_SIZE_CLASS_SMALL);
    aad.extend_from_slice(&SENDER_ENDPOINT);
    aad.extend_from_slice(&RECEIVER_ENDPOINT);
    aad.extend_from_slice(&CONNECTION_ID);
    aad.extend_from_slice(&expected_nonce);

    let plaintext = xchacha20poly1305_decrypt(&secret, &aad, &expected_nonce, ciphertext_bytes)
        .expect("AEAD opens with the same secret + AAD");
    assert_eq!(plaintext, inner);
}

#[test]
fn pick_size_class_picks_small_for_in_budget_payloads_and_rejects_oversize() {
    assert_eq!(pick_size_class(0).unwrap(), TransitFrameSizeClass::Small);
    assert_eq!(
        pick_size_class(TRANSIT_SMALL_PLAINTEXT_BYTES).unwrap(),
        TransitFrameSizeClass::Small
    );
    assert_eq!(
        pick_size_class(TRANSIT_SMALL_PLAINTEXT_BYTES + 1).unwrap(),
        TransitFrameSizeClass::Large
    );
    assert_eq!(
        pick_size_class(TRANSIT_LARGE_PLAINTEXT_BYTES).unwrap(),
        TransitFrameSizeClass::Large
    );
    let err = pick_size_class(TRANSIT_LARGE_PLAINTEXT_BYTES + 1)
        .expect_err("over-sized inner payload must be rejected");
    assert!(err.contains("refused inner payload"), "{err}");
}

#[test]
fn package_transit_frame_rejects_oversized_inner_payload() {
    let secret = [0x22u8; 32];
    let too_big = vec![0u8; TRANSIT_LARGE_PLAINTEXT_BYTES + 1];

    let err = package_transit_frame(
        &secret,
        &SENDER_ENDPOINT,
        &RECEIVER_ENDPOINT,
        &CONNECTION_ID,
        &too_big,
    )
    .expect_err("over-sized payload must be refused before AEAD");
    assert!(err.contains("refused inner payload"), "{err}");
}

#[test]
fn derive_transit_nonce_is_deterministic_and_input_sensitive() {
    let inner = b"some-inner-payload".to_vec();
    let n1 = derive_transit_nonce(&CONNECTION_ID, &inner);
    let n2 = derive_transit_nonce(&CONNECTION_ID, &inner);
    assert_eq!(n1, n2, "derivation must be deterministic");

    let mut other_conn = CONNECTION_ID;
    other_conn[0] ^= 0xFF;
    assert_ne!(derive_transit_nonce(&other_conn, &inner), n1);

    let mut other_inner = inner.clone();
    other_inner.push(0);
    assert_ne!(derive_transit_nonce(&CONNECTION_ID, &other_inner), n1);
}

#[test]
fn transit_network_send_intent_carries_frame_bytes_and_connection_id() {
    let frame = vec![0xAB; 64];
    let intent =
        transit_network_send_intent(CONNECTION_ID, frame.clone()).expect("build network send intent");
    assert_eq!(intent.kind.as_str(), TRANSIT_NETWORK_SEND);
    assert!(intent.payload.windows(frame.len()).any(|w| w == frame));
    assert!(intent
        .payload
        .windows(CONNECTION_ID.len())
        .any(|w| w == CONNECTION_ID));
}

#[test]
fn handler_stops_at_secret_context_stub_for_well_formed_intent() {
    let fact = Fact::new(FactScope::Global, 1, sendable_fact_bytes(7));
    let intent = send_on_connection_intent(TransitSendOnConnection {
        connection_id: CONNECTION_ID,
        fact_ids: vec![fact.id],
    });
    let context = HandlerContext::with_facts([fact]);

    let err = TransitSendOnConnectionHandler::new()
        .handle(&intent, &context)
        .expect_err("inner AEAD context not yet wired; intent must stay queued");
    assert_eq!(err, SECRET_CONTEXT_NOT_WIRED);
}

#[test]
fn handler_rejects_oversized_inner_payload_before_stopping_at_stub() {
    // Build a single sendable fact whose bytes exceed the large frame budget.
    let mut huge = vec![0xA0u8];
    huge.resize(TRANSIT_LARGE_PLAINTEXT_BYTES + 64, 0xCD);

    let fact = Fact::new(FactScope::Global, 1, huge);
    let intent = send_on_connection_intent(TransitSendOnConnection {
        connection_id: CONNECTION_ID,
        fact_ids: vec![fact.id],
    });
    let context = HandlerContext::with_facts([fact]);

    let err = TransitSendOnConnectionHandler::new()
        .handle(&intent, &context)
        .expect_err("over-sized inner payload must be rejected, not silently queued");
    assert!(
        err.contains("refused inner payload"),
        "expected size-class rejection, got: {err}"
    );
    assert_ne!(err, SECRET_CONTEXT_NOT_WIRED);
}

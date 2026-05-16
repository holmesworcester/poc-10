//! Receive-transit handler wiring tests.

use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::core::wake_loop::WakeLoop;
use topo::core::wire::FixedBytes;
use topo::event_modules::connection_response::fact::ConnectionResponseFact;
use topo::event_modules::connection_response::layout as connection_response_layout;
use topo::event_modules::encryption::fact::{
    KeyWrapFact, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
};
use topo::event_modules::encryption::{create as encryption_create, layout as encryption_layout};
use topo::event_modules::signed_fact;
use topo::event_modules::sync_compare::fact::{RangeSummary, SyncCompareFact, TimestampRange};
use topo::event_modules::sync_compare::layout as sync_compare_layout;
use topo::event_modules::transit::frame::{
    self as transit_frame, SealConnectionFrame, TransitFactBundle,
};
use topo::event_modules::transit::layout::{
    self as transit_layout, TRANSIT_FRAME_SIZE_CLASS_LARGE,
};
use topo::event_modules::transit_received;
use topo::handlers::receive_transit::{
    receive_transit_frame_intent, ReceiveTransitFrame, ReceiveTransitHandler, RECEIVE_TRANSIT_FRAME,
};

const ORIGIN: &[u8] = b"127.0.0.1:41001";
const RECEIVED_AT: u64 = 1_700_000_222;

fn receive_intent(frame: Vec<u8>) -> topo::core::intents::Intent {
    receive_intent_from_origin(frame, ORIGIN)
}

fn receive_intent_from_origin(frame: Vec<u8>, origin: &[u8]) -> topo::core::intents::Intent {
    receive_transit_frame_intent(ReceiveTransitFrame {
        frame,
        origin_addr: origin.to_vec(),
        received_at_local_ms: RECEIVED_AT,
    })
    .expect("receive intent")
}

fn connection_fact() -> (Fact, ConnectionResponseFact) {
    let connection = ConnectionResponseFact {
        from_endpoint: [10; 32],
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

fn signed_key_wrap_bytes() -> Vec<u8> {
    let signer_private_key = [31; 32];
    let signer_id = [32; 32];
    let wrap = KeyWrapFact {
        workspace_id: [21; 32],
        created_at_ms: 1_700_000_111,
        signer_endpoint_id: signer_id,
        frontier_id: [22; 32],
        wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
        wrapped_secret_id: [23; 32],
        wrapped_source_secret_id: [0; 32],
        wrapped_tombstone_node_id: [0; 32],
        range_start: 0,
        range_width: 0,
        bit_depth: 0,
        event_id_prefix: [0; 32],
        recipient_key_id: [24; 32],
        sender_wrap_public_key: [25; 32],
        nonce: [26; 24],
        ciphertext: [27; KEY_WRAP_CIPHERTEXT_BYTES],
    };
    signed_fact::create::sign_payload_bytes(
        signer_id,
        &signer_private_key,
        encryption_layout::encode_key_wrap(&wrap).expect("key wrap"),
    )
    .expect("signed key wrap")
}

fn encrypted_small_frame() -> (Vec<u8>, Fact, ConnectionResponseFact, Vec<u8>) {
    let (connection_fact, connection) = connection_fact();
    let signed_wrap = signed_key_wrap_bytes();
    let frame = transit_frame::seal_connection_frame(SealConnectionFrame {
        connection_id: connection_fact.id,
        sender_endpoint_id: connection.from_endpoint,
        receiver_endpoint_id: connection.to_endpoint,
        connection_secret: connection.connection_secret,
        nonce: [19; 24],
        facts: TransitFactBundle::from_bytes([signed_wrap.clone()]),
    })
    .expect("seal transit frame");
    (frame, connection_fact, connection, signed_wrap)
}

#[test]
fn well_formed_frame_opens_signed_key_wrap_and_records_receive_provenance() {
    let (frame, connection_fact, connection, signed_wrap) = encrypted_small_frame();
    let intent = receive_intent(frame.clone());
    assert_eq!(intent.kind.as_str(), RECEIVE_TRANSIT_FRAME);

    let output = ReceiveTransitHandler::new()
        .handle(
            &intent,
            &HandlerContext::with_facts([connection_fact.clone()]),
        )
        .expect("receive transit opens frame");

    assert_eq!(output.facts.len(), 2);
    let admitted_wrap =
        encryption_create::admit_signed_key_wrap_fact(signed_wrap).expect("admit expected wrap");
    assert!(
        output.facts.iter().any(|fact| *fact == admitted_wrap),
        "opened frame should emit the admitted signed key-wrap fact"
    );
    let provenance_fact = output
        .facts
        .iter()
        .find(|fact| fact.scope == FactScope::Local && fact.id != admitted_wrap.id)
        .expect("local provenance fact");
    let provenance =
        transit_received::layout::decode_fact(&provenance_fact.bytes).expect("decode provenance");
    assert_eq!(provenance.received_fact_id, admitted_wrap.id);
    assert_eq!(provenance.origin_addr, ORIGIN);
    assert_eq!(provenance.local_endpoint_id, connection.to_endpoint);
    assert_eq!(provenance.sender_endpoint_id, connection.from_endpoint);
    assert_eq!(provenance.connection_id, Some(connection_fact.id));
    assert_eq!(provenance.request_id, Some(connection.request_id));
    assert_eq!(provenance.frame_hash, crypto::hash(&frame));
    assert_eq!(provenance.received_at_local_ms, RECEIVED_AT);
}

#[test]
fn friendly_origin_addr_is_normalized_before_receive_provenance_fact() {
    let (frame, connection_fact, _, signed_wrap) = encrypted_small_frame();
    let intent = receive_intent_from_origin(frame, b"127.0.0.1_41001");

    let output = ReceiveTransitHandler::new()
        .handle(&intent, &HandlerContext::with_facts([connection_fact]))
        .expect("receive transit opens frame");

    let admitted_wrap =
        encryption_create::admit_signed_key_wrap_fact(signed_wrap).expect("admit expected wrap");
    let provenance_fact = output
        .facts
        .iter()
        .find(|fact| fact.scope == FactScope::Local && fact.id != admitted_wrap.id)
        .expect("local provenance fact");
    let provenance =
        transit_received::layout::decode_fact(&provenance_fact.bytes).expect("decode provenance");

    assert_eq!(provenance.origin_addr, ORIGIN);
}

#[test]
fn well_formed_frame_admits_sync_compare_and_records_receive_provenance() {
    let (connection_fact, connection) = connection_fact();
    let compare_bytes = sync_compare_layout::encode_fact(&SyncCompareFact {
        connection_id: connection_fact.id,
        range: TimestampRange { start: 10, end: 20 },
        summary: RangeSummary {
            count: 0,
            fingerprint: [0; 32],
        },
        response_requested: true,
    })
    .expect("sync compare");
    let frame = transit_frame::seal_connection_frame(SealConnectionFrame {
        connection_id: connection_fact.id,
        sender_endpoint_id: connection.from_endpoint,
        receiver_endpoint_id: connection.to_endpoint,
        connection_secret: connection.connection_secret,
        nonce: [29; 24],
        facts: TransitFactBundle::from_bytes([compare_bytes.clone()]),
    })
    .expect("seal transit frame");
    let intent = receive_intent(frame);

    let output = ReceiveTransitHandler::new()
        .handle(&intent, &HandlerContext::with_facts([connection_fact]))
        .expect("receive transit opens sync compare");

    assert_eq!(output.facts.len(), 2);
    let admitted = Fact::new(FactScope::Global, 0, compare_bytes);
    assert!(output.facts.iter().any(|fact| *fact == admitted));
    let provenance_fact = output
        .facts
        .iter()
        .find(|fact| fact.scope == FactScope::Local)
        .expect("local provenance fact");
    let provenance =
        transit_received::layout::decode_fact(&provenance_fact.bytes).expect("decode provenance");
    assert_eq!(provenance.received_fact_id, admitted.id);
}

#[test]
fn wake_loop_receive_dispatch_admits_opened_facts() {
    let (frame, connection_fact, _, signed_wrap) = encrypted_small_frame();
    let admitted_wrap =
        encryption_create::admit_signed_key_wrap_fact(signed_wrap).expect("admit expected wrap");
    let mut bus = WakeLoop::new();
    assert!(bus.submit_fact(connection_fact));
    bus.submit_intent(receive_intent(frame))
        .expect("queue receive intent");

    let report = bus
        .dispatch_deferred_intents_with_fact_context(&ReceiveTransitHandler::new(), 10)
        .expect("dispatch receive transit");

    assert_eq!(report.handled, 1);
    assert_eq!(report.facts, 2);
    assert!(bus.has_fact(&admitted_wrap.id));
    assert!(bus.intents().is_empty());
}

#[test]
fn well_formed_large_frame_resolves_connection_without_materializing_large_slot() {
    let (connection_fact, connection) = connection_fact();
    let frame = transit_layout::encode_frame_bytes(
        TRANSIT_FRAME_SIZE_CLASS_LARGE,
        FixedBytes(connection.from_endpoint),
        FixedBytes(connection.to_endpoint),
        FixedBytes(connection_fact.id),
        FixedBytes([19; 24]),
        b"not-opened-without-context",
    )
    .expect("large frame");
    let intent = receive_intent(frame);

    let err = ReceiveTransitHandler::new()
        .handle(&intent, &HandlerContext::new())
        .expect_err("missing connection context keeps intent queued");

    assert!(err.contains("missing fact"), "{err}");
}

#[test]
fn malformed_frame_header_is_rejected_before_inner_open() {
    let intent = receive_intent(vec![0u8; 32]);
    let handler = ReceiveTransitHandler::new();

    let err = handler
        .handle(&intent, &HandlerContext::new())
        .expect_err("frame too short to contain header");

    assert!(
        err.contains("WrongLength"),
        "malformed frames must be rejected at the envelope: {err}"
    );
}

#[test]
fn truncated_small_frame_after_valid_header_is_rejected() {
    let (mut bytes, _, _, _) = encrypted_small_frame();
    bytes.truncate(bytes.len() - 1);
    let intent = receive_intent(bytes);

    let err = ReceiveTransitHandler::new()
        .handle(&intent, &HandlerContext::new())
        .expect_err("truncated frame must not reach connection lookup");

    assert!(
        err.contains("WrongLength"),
        "truncated frames must be rejected at envelope decode: {err}"
    );
}

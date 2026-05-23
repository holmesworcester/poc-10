//! Receive-network handler and connection-frame projector wiring tests.

use topo::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, IntentHandler};
use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
use topo::core::wire::FixedBytes;
use topo::protocol::connection;
use topo::protocol::connection::request::fact::ConnectionRequestFact;
use topo::protocol::connection::request::layout as connection_request_layout;
use topo::protocol::connection::response::fact::ConnectionResponseFact;
use topo::protocol::connection::response::layout as connection_response_layout;
use topo::protocol::encryption::key_wrap::create as encryption_create;
use topo::protocol::encryption::key_wrap::fact::{
    KeyWrapFact, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
};
use topo::protocol::encryption::key_wrap::layout as encryption_layout;
use topo::protocol::identity;
use topo::protocol::identity::endpoint::fact::EndpointFact;
use topo::protocol::identity::invite::fact::InviteSecretFact;
use topo::protocol::identity::invite::layout as invite_layout;
use topo::protocol::sync::compare::fact::{RangeSummary, SyncCompareFact, TimestampRange};
use topo::protocol::sync::compare::layout as sync_compare_layout;
use topo::protocol::transport::connection_frame::fact::{
    ConnectionFrameLargeFact, ConnectionFrameSmallFact,
};
use topo::protocol::transport::connection_frame::frame::{
    self as connection_frame, ConnectionFrameFactBundle, SealConnectionFrame,
};
use topo::protocol::transport::connection_frame::layout::{
    self as frame_layout, CONNECTION_FRAME_SIZE_CLASS_LARGE,
};
use topo::protocol::transport::connection_frame::project::ConnectionFrameProjector;
use topo::protocol::transport::receive_network_frame::{
    receive_network_frame_intent, ReceiveNetworkFrame, ReceiveNetworkFrameHandler,
    RECEIVE_NETWORK_FRAME,
};

const ORIGIN: &[u8] = b"127.0.0.1:41001";
const RECEIVED_AT: u64 = 1_700_000_222;

fn receive_intent(frame: Vec<u8>) -> topo::core::intents::Intent {
    receive_intent_from_origin(frame, ORIGIN)
}

fn receive_intent_from_origin(frame: Vec<u8>, origin: &[u8]) -> topo::core::intents::Intent {
    receive_network_frame_intent(ReceiveNetworkFrame {
        frame,
        origin_addr: origin.to_vec(),
        received_at_local_ms: RECEIVED_AT,
    })
    .expect("receive intent")
}

fn connection_frame_small_fact(frame: Vec<u8>) -> Fact {
    let input = ConnectionFrameSmallFact {
        frame,
        origin_addr: ORIGIN.to_vec(),
        received_at_local_ms: RECEIVED_AT,
    };
    Fact::new(
        FactScope::Local,
        RECEIVED_AT,
        frame_layout::encode_small_fact(&input).expect("small connection frame"),
    )
}

fn connection_frame_large_fact(frame: Vec<u8>) -> Fact {
    let input = ConnectionFrameLargeFact {
        frame,
        origin_addr: ORIGIN.to_vec(),
        received_at_local_ms: RECEIVED_AT,
    };
    Fact::new(
        FactScope::Local,
        RECEIVED_AT,
        frame_layout::encode_large_fact(&input).expect("large connection frame"),
    )
}

fn project_connection_frame_fact(
    fact: &Fact,
    context: ProjectionContext,
) -> topo::core::projectors::ProjectionOutput {
    ConnectionFrameProjector::new()
        .project(fact, &context)
        .expect("project connection frame")
}

fn exact_match(
    owner: [u8; 32],
    role: &'static str,
    key: [u8; 32],
    payload: Fact,
) -> MatchedContext {
    let role = Role::from(role);
    let key = ContextKey::from_bytes(key);
    MatchedContext {
        need: ContextNeed {
            owner,
            role: role.clone(),
            scope: FactScope::Local,
            start_key: key.clone(),
            end_key: key.clone(),
        },
        offer: ContextOffer {
            owner: payload.id,
            role,
            scope: FactScope::Local,
            start_key: key.clone(),
            end_key: key,
        },
        payload,
    }
}

fn connection_fact() -> (Fact, ConnectionResponseFact) {
    let connection = ConnectionResponseFact {
        from_endpoint: [10; 32],
        to_endpoint: [11; 32],
        request_id: [12; 32],
        invite_secret_fact_id: [13; 32],
        initiator_ephemeral_secret_fact_id: [14; 32],
        responder_ephemeral_secret_fact_id: [15; 32],
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
        fact_id_prefix: [0; 32],
        recipient_key_id: [24; 32],
        sender_wrap_public_key: [25; 32],
        nonce: [26; 24],
        ciphertext: [27; KEY_WRAP_CIPHERTEXT_BYTES],
    };
    identity::signed_fact::create::sign_payload_bytes(
        signer_id,
        &signer_private_key,
        encryption_layout::encode_key_wrap(&wrap).expect("key wrap"),
    )
    .expect("signed key wrap")
}

fn encrypted_small_frame() -> (Vec<u8>, Fact, ConnectionResponseFact, Vec<u8>) {
    let (connection_fact, connection) = connection_fact();
    let signed_wrap = signed_key_wrap_bytes();
    let frame = connection_frame::seal_connection_frame(SealConnectionFrame {
        connection_id: connection_fact.id,
        sender_endpoint_id: connection.from_endpoint,
        receiver_endpoint_id: connection.to_endpoint,
        connection_secret: connection.connection_secret,
        nonce: [19; 24],
        facts: ConnectionFrameFactBundle::from_bytes([signed_wrap.clone()]),
    })
    .expect("seal transport::connection_frame frame");
    (frame, connection_fact, connection, signed_wrap)
}

#[test]
fn receive_handler_emits_ephemeral_connection_frame_small() {
    let (frame, _, _, _) = encrypted_small_frame();
    let intent = receive_intent(frame.clone());
    assert_eq!(intent.kind.as_str(), RECEIVE_NETWORK_FRAME);

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&intent, &HandlerContext::new())
        .expect("receive intent becomes connection frame input");

    assert!(output.facts.is_empty());
    assert_eq!(output.ephemeral_facts.len(), 1);
    let input = frame_layout::decode_small_fact(output.ephemeral_facts[0].body())
        .expect("decode small connection frame");
    assert_eq!(input.frame, frame);
    assert_eq!(input.origin_addr, ORIGIN);
    assert_eq!(input.received_at_local_ms, RECEIVED_AT);
}

#[test]
fn receive_handler_emits_durable_bootstrap_request_and_receipt_only() {
    let invite = InviteSecretFact::new([33; 32]);
    let invite_fact = Fact::new(
        FactScope::Local,
        10,
        invite_layout::encode_fact(&invite).expect("invite"),
    );
    let endpoint = local_endpoint();
    let mut request = ConnectionRequestFact {
        from_endpoint: crypto::x25519_public_key(&[55; 32]),
        to_endpoint: endpoint.endpoint,
        nonce: [56; 32],
        invite_fact_id: [57; 32],
        bootstrap_hash: invite.bootstrap_hash,
        invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        invite_secret_fact_id: invite_fact.id,
        initiator_ephemeral_secret_fact_id: [58; 32],
        initiator_ephemeral_public_key: crypto::x25519_public_key(&[59; 32]),
        from_listen_addr: Some("127.0.0.1:41001".parse().expect("return addr")),
        to_listen_addr: None,
    };
    request.invite_signature = crypto::ed25519_sign(
        &invite.bootstrap_secret,
        &topo::protocol::connection::request::create::invite_signing_transcript(&request)
            .expect("request transcript"),
    );
    let frame = connection_request_layout::encode_fact(&request).expect("request");
    let expected_request = Fact::new(FactScope::Global, RECEIVED_AT, frame.clone());

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(frame.clone()), &HandlerContext::new())
        .expect("receive request");

    assert!(output.ephemeral_facts.is_empty());
    assert_eq!(output.facts.len(), 2);
    assert!(output.facts.iter().any(|fact| *fact == expected_request));
    assert!(output.intents.is_empty());
    assert!(output.facts.iter().all(|fact| {
        !matches!(
            fact.body().first().copied(),
            Some(connection_response_layout::TYPE_CONNECTION_RESPONSE)
                | Some(topo::protocol::connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET)
        )
    }));
    let receipt_fact = output
        .facts
        .iter()
        .find(|fact| {
            fact.body().first().copied()
                == Some(connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT)
        })
        .expect("receipt fact");
    let receipt =
        connection::fact_receipt::layout::decode_fact(receipt_fact.body()).expect("decode receipt");
    assert_eq!(receipt.received_fact_id, expected_request.id);
    assert_eq!(receipt.local_endpoint_id, request.to_endpoint);
    assert_eq!(receipt.sender_endpoint_id, request.from_endpoint);
    assert_eq!(receipt.request_id, Some(expected_request.id));
    assert_eq!(receipt.frame_hash, crypto::hash(&frame));
}

#[test]
fn well_formed_frame_opens_signed_key_wrap_and_records_fact_receipt() {
    let (frame, connection_fact, connection, signed_wrap) = encrypted_small_frame();
    let input_fact = connection_frame_small_fact(frame.clone());
    let context = ProjectionContext::from_matches(vec![exact_match(
        input_fact.id,
        "connection_response",
        connection_fact.id,
        connection_fact.clone(),
    )]);

    let output = project_connection_frame_fact(&input_fact, context);

    assert_eq!(output.effects.facts.len(), 2);
    let admitted_wrap =
        encryption_create::admit_signed_key_wrap_fact(signed_wrap).expect("admit expected wrap");
    assert!(
        output
            .effects
            .facts
            .iter()
            .any(|fact| *fact == admitted_wrap),
        "opened frame should emit the admitted signed key-wrap fact"
    );
    let receipt_fact = output
        .effects
        .facts
        .iter()
        .find(|fact| fact.scope == FactScope::Local && fact.id != admitted_wrap.id)
        .expect("local receipt fact");
    let receipt =
        connection::fact_receipt::layout::decode_fact(&receipt_fact.bytes).expect("decode receipt");
    assert_eq!(receipt.received_fact_id, admitted_wrap.id);
    assert_eq!(receipt.origin_addr, ORIGIN);
    assert_eq!(receipt.local_endpoint_id, connection.to_endpoint);
    assert_eq!(receipt.sender_endpoint_id, connection.from_endpoint);
    assert_eq!(receipt.connection_id, Some(connection_fact.id));
    assert_eq!(receipt.request_id, Some(connection.request_id));
    assert_eq!(receipt.frame_hash, crypto::hash(&frame));
    assert_eq!(receipt.received_at_local_ms, RECEIVED_AT);
}

#[test]
fn friendly_origin_addr_is_normalized_before_receive_projection_input() {
    let (frame, _, _, _) = encrypted_small_frame();
    let intent = receive_intent_from_origin(frame, b"127.0.0.1_41001");

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&intent, &HandlerContext::new())
        .expect("receive transport::connection_frame stages input");

    let input = frame_layout::decode_small_fact(output.ephemeral_facts[0].body())
        .expect("decode small connection frame");
    assert_eq!(input.origin_addr, ORIGIN);
}

#[test]
fn well_formed_frame_admits_sync_compare_and_records_fact_receipt() {
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
    let frame = connection_frame::seal_connection_frame(SealConnectionFrame {
        connection_id: connection_fact.id,
        sender_endpoint_id: connection.from_endpoint,
        receiver_endpoint_id: connection.to_endpoint,
        connection_secret: connection.connection_secret,
        nonce: [29; 24],
        facts: ConnectionFrameFactBundle::from_bytes([compare_bytes.clone()]),
    })
    .expect("seal transport::connection_frame frame");
    let input_fact = connection_frame_small_fact(frame);
    let context = ProjectionContext::from_matches(vec![exact_match(
        input_fact.id,
        "connection_response",
        connection_fact.id,
        connection_fact,
    )]);

    let output = project_connection_frame_fact(&input_fact, context);

    assert_eq!(output.effects.facts.len(), 2);
    let admitted = Fact::new(FactScope::Global, 0, compare_bytes);
    assert!(output.effects.facts.iter().any(|fact| *fact == admitted));
    let receipt_fact = output
        .effects
        .facts
        .iter()
        .find(|fact| fact.scope == FactScope::Local)
        .expect("local receipt fact");
    let receipt =
        connection::fact_receipt::layout::decode_fact(&receipt_fact.bytes).expect("decode receipt");
    assert_eq!(receipt.received_fact_id, admitted.id);
}

#[test]
fn well_formed_large_frame_can_park_before_materializing_large_slot() {
    let (connection_fact, connection) = connection_fact();
    let frame = frame_layout::encode_frame_bytes(
        CONNECTION_FRAME_SIZE_CLASS_LARGE,
        FixedBytes(connection.from_endpoint),
        FixedBytes(connection.to_endpoint),
        FixedBytes(connection_fact.id),
        FixedBytes([19; 24]),
        b"not-opened-without-context",
    )
    .expect("large frame");
    let input_fact = connection_frame_large_fact(frame);

    let output = project_connection_frame_fact(&input_fact, ProjectionContext::default());

    assert_eq!(output.needs.len(), 1);
    assert_eq!(output.needs[0].role, "connection_response");
    assert!(output.effects.facts.is_empty());
}

#[test]
fn malformed_frame_header_is_discarded_by_receive_handler() {
    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(vec![0u8; 32]), &HandlerContext::new())
        .expect("malformed frame is consumed");

    assert!(output.facts.is_empty());
    assert!(output.ephemeral_facts.is_empty());
}

#[test]
fn truncated_small_frame_after_valid_header_is_discarded_by_receive_handler() {
    let (mut bytes, _, _, _) = encrypted_small_frame();
    bytes.truncate(bytes.len() - 1);

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(bytes), &HandlerContext::new())
        .expect("truncated frame is consumed");

    assert!(output.facts.is_empty());
    assert!(output.ephemeral_facts.is_empty());
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

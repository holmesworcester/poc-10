//! Receive-network handler and connection-frame projector wiring tests.

use topo::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use topo::core::crypto;
use topo::core::effects::RuntimeEffects;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, IntentHandler};
use topo::core::project_fact::{MatchedContext, ProjectionContext, Projector};
use topo::core::wire::{FixedBytes, FixedSlot};
use topo::protocol::auth::endpoint::encode as endpoint_layout;
use topo::protocol::auth::endpoint::fact::EndpointFact;
use topo::protocol::auth::invite::fact::InviteSecretFact;
use topo::protocol::auth::key_wrap::author as auth_create;
use topo::protocol::auth::key_wrap::encode as auth_layout;
use topo::protocol::auth::key_wrap::fact::{
    KeyWrapFact, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
};
use topo::protocol::connection;
use topo::protocol::connection::connection::encode as connection_layout_encode;
use topo::protocol::connection::connection::fact::ConnectionFact;
use topo::protocol::connection::connection::project::decode as connection_layout_decode;
use topo::protocol::connection::frame_bundle::encode::{
    self as frame_bundle_layout_encode, CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
};
use topo::protocol::connection::frame_bundle::fact::ConnectionFrameBundleFact;
use topo::protocol::connection::frame_bundle::project::decode as frame_bundle_layout_decode;
use topo::protocol::connection::frame_bundle::project::ConnectionFrameBundleProjector;
use topo::protocol::connection::frame_file_slice::encode::{
    self as frame_file_slice_layout_encode, CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES,
};
use topo::protocol::connection::frame_file_slice::project::decode as frame_file_slice_layout_decode;
use topo::protocol::connection::frame_observation::author as frame_observation_create;
use topo::protocol::connection::frame_observation::project::decode as frame_observation_layout_decode;
use topo::protocol::connection::frame_small::author as frame_small_author;
use topo::protocol::connection::frame_small::encode::{
    self as frame_small_layout_encode, CONNECTION_FRAME_SMALL_WIRE_BYTES,
};
use topo::protocol::connection::frame_small::fact::ConnectionFrameSmallFact;
use topo::protocol::connection::frame_small::project::decode as frame_small_layout_decode;
use topo::protocol::connection::frame_small::project::ConnectionFrameSmallProjector;
use topo::protocol::connection::receive_network_frame::{
    receive_network_frame_intent, ReceiveNetworkFrame, ReceiveNetworkFrameHandler,
    RECEIVE_NETWORK_FRAME,
};
use topo::protocol::connection::request::encode as connection_request_layout_encode;
use topo::protocol::connection::request::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP};
use topo::protocol::connection::request::project::decode as connection_request_layout_decode;
use topo::protocol::sync::compare::encode as sync_compare_layout;
use topo::protocol::sync::compare::fact::{RangeSummary, SyncCompareFact, TimestampRange};

const ORIGIN: &[u8] = b"127.0.0.1:41001";
const RECEIVED_AT: u64 = 1_700_000_222;

fn on_big_stack<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

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
        frame: FixedSlot::<CONNECTION_FRAME_SMALL_WIRE_BYTES>::new(&frame).expect("small frame"),
    };
    Fact::new(
        FactScope::Local,
        RECEIVED_AT,
        frame_small_layout_encode::encode_fact(&input).expect("small connection frame"),
    )
}

fn connection_frame_bundle_fact(frame: Vec<u8>) -> Fact {
    let input = ConnectionFrameBundleFact {
        frame: FixedSlot::<CONNECTION_FRAME_BUNDLE_WIRE_BYTES>::new(&frame).expect("bundle frame"),
    };
    Fact::new(
        FactScope::Local,
        RECEIVED_AT,
        frame_bundle_layout_encode::encode_fact(&input).expect("bundle connection frame"),
    )
}

fn assert_observation_fact(
    output: &RuntimeEffects,
    frame_fact_id: [u8; 32],
) -> topo::protocol::connection::frame_observation::fact::ConnectionFrameObservationFact {
    assert!(output.intents.is_empty());
    assert!(output.local_intents.is_empty());
    let observation = output
        .facts
        .iter()
        .filter_map(|fact| frame_observation_layout_decode::decode_fact(fact.body()).ok())
        .find(|observation| observation.frame_fact_id == frame_fact_id)
        .expect("frame observation fact");
    assert_eq!(observation.frame_fact_id, frame_fact_id);
    assert_eq!(observation.origin_addr, ORIGIN);
    assert_eq!(observation.received_at_local_ms, RECEIVED_AT);
    observation
}

fn project_connection_frame_fact(
    fact: &Fact,
    context: ProjectionContext,
) -> topo::core::project_fact::ProjectionOutput {
    match fact.body().first().copied() {
        Some(frame_small_layout_encode::TYPE_CONNECTION_FRAME_SMALL) => {
            ConnectionFrameSmallProjector::new()
                .project(fact, &context)
                .expect("project small connection frame")
        }
        Some(frame_bundle_layout_encode::TYPE_CONNECTION_FRAME_BUNDLE) => {
            ConnectionFrameBundleProjector::new()
                .project(fact, &context)
                .expect("project bundle connection frame")
        }
        other => panic!("unexpected connection frame fact tag {other:?}"),
    }
}

fn exact_match(
    owner: [u8; 32],
    role: &'static str,
    scope: FactScope,
    key: [u8; 32],
    payload: Fact,
) -> MatchedContext {
    let role = Role::from(role);
    let key = ContextKey::from_bytes(key);
    MatchedContext {
        need: ContextNeed {
            owner,
            role: role.clone(),
            scope: scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
        },
        offer: ContextOffer {
            owner: payload.id,
            role,
            scope,
            start_key: key.clone(),
            end_key: key,
        },
        payload,
    }
}

fn observation_match(frame_fact: &Fact) -> MatchedContext {
    let observation =
        frame_observation_create::fact_from_observation(frame_fact.id, ORIGIN, RECEIVED_AT)
            .expect("frame observation");
    exact_match(
        frame_fact.id,
        "connection_frame_observation",
        FactScope::Local,
        frame_fact.id,
        observation,
    )
}

fn local_endpoint_match(frame_fact_id: [u8; 32], endpoint: &EndpointFact) -> MatchedContext {
    let endpoint_fact = Fact::new(
        FactScope::Local,
        0,
        endpoint_layout::encode_fact(endpoint).expect("encode endpoint"),
    );
    MatchedContext {
        need: ContextNeed::range(
            frame_fact_id,
            "auth_local_endpoint",
            FactScope::Local,
            [0u8; 32],
            [0xffu8; 32],
        ),
        offer: ContextOffer::range(
            endpoint_fact.id,
            "auth_local_endpoint",
            FactScope::Local,
            endpoint.endpoint,
            endpoint.endpoint,
        ),
        payload: endpoint_fact,
    }
}

fn observed_connection_context(
    frame_fact: &Fact,
    connection_fact: Fact,
    local_endpoint: &EndpointFact,
) -> ProjectionContext {
    ProjectionContext::from_matches(vec![
        observation_match(frame_fact),
        exact_match(
            frame_fact.id,
            "connection",
            FactScope::Local,
            connection_fact.id,
            connection_fact,
        ),
        local_endpoint_match(frame_fact.id, local_endpoint),
    ])
}

fn connection_fact() -> (Fact, ConnectionFact, EndpointFact) {
    let local_endpoint = local_endpoint();
    let responder_ephemeral_private = [15; 32];
    let connection = ConnectionFact {
        from_endpoint: [10; 32],
        to_endpoint: local_endpoint.endpoint,
        request_id: [12; 32],
        responder_addr: None,
        initiator_addr: None,
        initiator_ephemeral_secret_fact_id: [14; 32],
        responder_ephemeral_secret_fact_id: [15; 32],
        responder_ephemeral_public_key: crypto::x25519_public_key(&responder_ephemeral_private),
        handshake_hash: [17; 32],
        connection_secret: [18; 32],
    };
    let fact = Fact::new(
        FactScope::Local,
        1,
        connection_layout_encode::seal_fact(&connection, &responder_ephemeral_private)
            .expect("connection"),
    );
    (fact, connection, local_endpoint)
}

fn key_wrap_bytes() -> Vec<u8> {
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
    auth_layout::encode_key_wrap(&wrap).expect("key wrap")
}

fn encrypted_small_frame() -> (Vec<u8>, Fact, ConnectionFact, EndpointFact, Vec<u8>) {
    let (connection_fact, connection, local_endpoint) = connection_fact();
    let signed_wrap = key_wrap_bytes();
    let frame = frame_small_author::seal_connection_frame(
        connection_fact.id,
        connection.from_endpoint,
        connection.to_endpoint,
        connection.connection_secret,
        [19; 24],
        &[signed_wrap.clone()],
    )
    .expect("seal connection::frame frame");
    (
        frame,
        connection_fact,
        connection,
        local_endpoint,
        signed_wrap,
    )
}

#[test]
fn receive_handler_emits_ephemeral_connection_frame_small() {
    let (frame, _, _, _, _) = encrypted_small_frame();
    let intent = receive_intent(frame.clone());
    assert_eq!(intent.kind.as_str(), RECEIVE_NETWORK_FRAME);

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&intent, &HandlerContext::new())
        .expect("receive intent becomes connection frame input");

    assert_eq!(output.facts.len(), 1);
    assert_eq!(output.incoming_facts.len(), 1);
    let input = frame_small_layout_decode::decode_fact(output.incoming_facts[0].body())
        .expect("decode small connection frame");
    assert_eq!(input.frame, frame);
    assert_observation_fact(&output, output.incoming_facts[0].id);
}

#[test]
fn receive_handler_emits_ephemeral_connection_frame_file_slice() {
    let frame = frame_file_slice_layout_encode::encode_frame_bytes(
        FixedBytes([1; 32]),
        FixedBytes([2; 24]),
        b"classified file-slice frame",
    )
    .expect("file-slice frame");
    assert_eq!(frame.len(), CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES);

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(frame.clone()), &HandlerContext::new())
        .expect("receive intent becomes file-slice connection frame input");

    assert_eq!(output.facts.len(), 1);
    assert_eq!(output.incoming_facts.len(), 1);
    let input = frame_file_slice_layout_decode::decode_fact(output.incoming_facts[0].body())
        .expect("decode file-slice connection frame");
    assert_eq!(input.frame, frame);
    assert_observation_fact(&output, output.incoming_facts[0].id);
}

#[test]
fn receive_handler_emits_ephemeral_connection_frame_bundle() {
    let frame = frame_bundle_layout_encode::encode_frame_bytes(
        FixedBytes([3; 32]),
        FixedBytes([4; 24]),
        b"classified bundle frame",
    )
    .expect("bundle frame");
    assert_eq!(frame.len(), CONNECTION_FRAME_BUNDLE_WIRE_BYTES);

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(frame.clone()), &HandlerContext::new())
        .expect("receive intent becomes bundle connection frame input");

    assert_eq!(output.facts.len(), 1);
    assert_eq!(output.incoming_facts.len(), 1);
    let input = frame_bundle_layout_decode::decode_fact(output.incoming_facts[0].body())
        .expect("decode bundle connection frame");
    assert_eq!(input.frame, frame);
    assert_observation_fact(&output, output.incoming_facts[0].id);
}

#[test]
fn sealed_request_frame_is_admitted_as_incoming_request_plus_observation() {
    let frame = sealed_request_frame();

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(frame.clone()), &HandlerContext::new())
        .expect("receive sealed request");

    assert_eq!(output.facts.len(), 1);
    assert_eq!(output.incoming_facts.len(), 1);
    let request_fact = output
        .incoming_facts
        .iter()
        .find(|fact| {
            fact.scope == FactScope::Global
                && fact.bytes == frame
                && connection_request_layout_decode::is_sealed_fact(fact.body())
        })
        .expect("sealed request fact");
    assert_observation_fact(&output, request_fact.id);
}

#[test]
fn raw_connection_request_bytes_are_discarded_at_the_network_boundary() {
    let request = plaintext_request();
    let frame = connection_request_layout_encode::encode_fact(&request).expect("request");

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(frame), &HandlerContext::new())
        .expect("raw request is consumed");

    assert!(output.facts.is_empty());
    assert!(output.incoming_facts.is_empty());
    assert!(output.intents.is_empty());
}

#[test]
fn raw_connection_bytes_are_discarded_at_the_network_boundary() {
    let connection = plaintext_connection();
    let frame = connection_layout_encode::encode_fact(&connection).expect("response");

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(frame), &HandlerContext::new())
        .expect("raw connection is consumed");

    assert!(output.facts.is_empty());
    assert!(output.incoming_facts.is_empty());
    assert!(output.intents.is_empty());
}

#[test]
fn sealed_connection_frame_is_admitted_as_incoming_connection_plus_observation() {
    let responder_ephemeral_private = [72; 32];
    let connection = ConnectionFact {
        from_endpoint: crypto::x25519_public_key(&[71; 32]),
        to_endpoint: local_endpoint().endpoint,
        request_id: [73; 32],
        responder_addr: None,
        initiator_addr: None,
        initiator_ephemeral_secret_fact_id: [75; 32],
        responder_ephemeral_secret_fact_id: [76; 32],
        responder_ephemeral_public_key: crypto::x25519_public_key(&responder_ephemeral_private),
        handshake_hash: [77; 32],
        connection_secret: [78; 32],
    };
    let frame = connection_layout_encode::seal_fact(&connection, &responder_ephemeral_private)
        .expect("seal connection");

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(frame.clone()), &HandlerContext::new())
        .expect("receive sealed connection");

    assert_eq!(output.facts.len(), 1);
    assert_eq!(output.incoming_facts.len(), 1);
    let connection_fact = output
        .incoming_facts
        .iter()
        .find(|fact| {
            fact.scope == FactScope::Local
                && fact.bytes == frame
                && connection_layout_decode::is_sealed_fact(fact.body())
        })
        .expect("sealed connection fact");
    assert_observation_fact(&output, connection_fact.id);
}

#[test]
fn well_formed_frame_opens_key_wrap_and_records_fact_receipt() {
    let (frame, connection_fact, connection, local_endpoint, signed_wrap) = encrypted_small_frame();
    let input_fact = connection_frame_small_fact(frame.clone());
    let context =
        observed_connection_context(&input_fact, connection_fact.clone(), &local_endpoint);

    let output = project_connection_frame_fact(&input_fact, context);

    assert_eq!(output.effects.incoming_facts.len(), 2);
    let admitted_wrap = auth_create::admit_key_wrap_fact(signed_wrap).expect("admit expected wrap");
    assert!(
        output.effects.incoming_facts.contains(&admitted_wrap),
        "opened frame should emit the admitted key-wrap fact"
    );
    let receipt_fact = output
        .effects
        .incoming_facts
        .iter()
        .find(|fact| fact.scope == FactScope::Local && fact.id != admitted_wrap.id)
        .expect("local receipt fact");
    let receipt = connection::fact_receipt::project::decode::decode_fact(&receipt_fact.bytes)
        .expect("decode receipt");
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
    let (frame, _, _, _, _) = encrypted_small_frame();
    let intent = receive_intent_from_origin(frame, b"127.0.0.1_41001");

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&intent, &HandlerContext::new())
        .expect("receive connection::frame stages input");

    let observation = assert_observation_fact(&output, output.incoming_facts[0].id);
    assert_eq!(observation.origin_addr, ORIGIN);
}

#[test]
fn well_formed_frame_admits_sync_compare_and_records_fact_receipt() {
    let (connection_fact, connection, local_endpoint) = connection_fact();
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
    let frame = frame_small_author::seal_connection_frame(
        connection_fact.id,
        connection.from_endpoint,
        connection.to_endpoint,
        connection.connection_secret,
        [29; 24],
        &[compare_bytes.clone()],
    )
    .expect("seal connection::frame frame");
    let input_fact = connection_frame_small_fact(frame);
    let context = observed_connection_context(&input_fact, connection_fact, &local_endpoint);

    let output = project_connection_frame_fact(&input_fact, context);

    assert_eq!(output.effects.incoming_facts.len(), 2);
    let admitted = Fact::new(FactScope::Global, 0, compare_bytes);
    assert!(output.effects.incoming_facts.contains(&admitted));
    let receipt_fact = output
        .effects
        .incoming_facts
        .iter()
        .find(|fact| fact.scope == FactScope::Local)
        .expect("local receipt fact");
    let receipt = connection::fact_receipt::project::decode::decode_fact(&receipt_fact.bytes)
        .expect("decode receipt");
    assert_eq!(receipt.received_fact_id, admitted.id);
}

#[test]
fn well_formed_bundle_frame_without_observation_context_emits_transient_need_only() {
    on_big_stack(|| {
        let (connection_fact, _, _) = connection_fact();
        let frame = frame_bundle_layout_encode::encode_frame_bytes(
            FixedBytes(connection_fact.id),
            FixedBytes([19; 24]),
            b"not-opened-without-context",
        )
        .expect("bundle frame");
        let input_fact = connection_frame_bundle_fact(frame);

        let output = project_connection_frame_fact(&input_fact, ProjectionContext::default());

        assert!(output.retain_self);
        assert_eq!(output.needs.len(), 1);
        assert_eq!(
            output.needs[0].role.as_str(),
            "connection_frame_observation"
        );
        assert!(output.effects.facts.is_empty());
    });
}

#[test]
fn well_formed_bundle_frame_without_connection_context_emits_transient_need_only() {
    on_big_stack(|| {
        let (connection_fact, _, _) = connection_fact();
        let frame = frame_bundle_layout_encode::encode_frame_bytes(
            FixedBytes(connection_fact.id),
            FixedBytes([19; 24]),
            b"not-opened-without-context",
        )
        .expect("bundle frame");
        let input_fact = connection_frame_bundle_fact(frame);
        let context = ProjectionContext::from_matches(vec![observation_match(&input_fact)]);

        let output = project_connection_frame_fact(&input_fact, context);

        assert!(output.retain_self);
        assert_eq!(output.needs.len(), 2);
        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "connection_frame_observation"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "connection"));
        assert!(output.effects.facts.is_empty());
    });
}

#[test]
fn malformed_frame_header_is_discarded_by_receive_handler() {
    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(vec![0u8; 32]), &HandlerContext::new())
        .expect("malformed frame is consumed");

    assert!(output.facts.is_empty());
    assert!(output.incoming_facts.is_empty());
    assert!(output.intents.is_empty());
}

#[test]
fn truncated_small_frame_after_valid_header_is_discarded_by_receive_handler() {
    let (mut bytes, _, _, _, _) = encrypted_small_frame();
    bytes.truncate(bytes.len() - 1);

    let output = ReceiveNetworkFrameHandler::new()
        .handle(&receive_intent(bytes), &HandlerContext::new())
        .expect("truncated frame is consumed");

    assert!(output.facts.is_empty());
    assert!(output.incoming_facts.is_empty());
    assert!(output.intents.is_empty());
}

fn sealed_request_frame() -> Vec<u8> {
    let invite = InviteSecretFact::new([33; 32]);
    let initiator_ephemeral_private = [59; 32];
    let mut request = plaintext_request();
    request.bootstrap_hash = invite.bootstrap_hash;
    request.invite_signature = [0; crypto::ED25519_SIGNATURE_BYTES];
    request.initiator_ephemeral_public_key =
        crypto::x25519_public_key(&initiator_ephemeral_private);
    connection::request::author::sign_bootstrap_request(&mut request, &invite)
        .expect("sign request");
    connection_request_layout_encode::seal_fact(&request, &initiator_ephemeral_private)
        .expect("seal request")
}

fn plaintext_request() -> ConnectionRequestFact {
    let endpoint = local_endpoint();
    ConnectionRequestFact {
        mode: REQUEST_MODE_BOOTSTRAP,
        from_endpoint: crypto::x25519_public_key(&[55; 32]),
        to_endpoint: endpoint.endpoint,
        nonce: [56; 32],
        dialed_addr: Some("127.0.0.1:41001".parse().expect("dialed addr")),
        initiator_addr: None,
        invite_fact_id: [57; 32],
        bootstrap_hash: [58; 32],
        invite_signature: [59; crypto::ED25519_SIGNATURE_BYTES],
        invite_secret_fact_id: [60; 32],
        initiator_endpoint_shared_id: [0; 32],
        endpoint_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        initiator_ephemeral_secret_fact_id: [61; 32],
        initiator_ephemeral_public_key: crypto::x25519_public_key(&[62; 32]),
    }
}

fn plaintext_connection() -> ConnectionFact {
    ConnectionFact {
        from_endpoint: crypto::x25519_public_key(&[63; 32]),
        to_endpoint: local_endpoint().endpoint,
        request_id: [64; 32],
        responder_addr: None,
        initiator_addr: None,
        initiator_ephemeral_secret_fact_id: [66; 32],
        responder_ephemeral_secret_fact_id: [67; 32],
        responder_ephemeral_public_key: crypto::x25519_public_key(&[68; 32]),
        handshake_hash: [69; 32],
        connection_secret: [70; 32],
    }
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

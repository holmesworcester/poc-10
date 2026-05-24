//! Behavioural tests for the target `connection::response` handler.
//!
//! The request projector schedules this handler only after exact invite and
//! fact-receipt context exists. The handler rechecks that context,
//! creates local responder ephemeral material, emits the response fact, and
//! sends the response bytes back to the request's bootstrap return address.

use std::io::Read;
use std::net::TcpListener;
use std::thread;

use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, IntentHandler};
use topo::core::network;
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::auth::endpoint::fact::EndpointFact;
use topo::protocol::auth::endpoint::rows as endpoint_rows;
use topo::protocol::auth::invite::fact::InviteSecretFact;
use topo::protocol::auth::invite::layout as invite_layout;
use topo::protocol::connection::bootstrap;
use topo::protocol::connection::create_response::{
    create_connection_response_intent, CreateConnectionResponse, CreateConnectionResponseHandler,
};
use topo::protocol::connection::ephemeral_secret::layout as ephemeral_layout;
use topo::protocol::connection::fact_receipt::fact::{
    ConnectionFactReceipt, RECEIVE_PATH_CONNECTION_REQUEST,
};
use topo::protocol::connection::fact_receipt::layout as received_layout;
use topo::protocol::connection::request::fact::ConnectionRequestFact;
use topo::protocol::connection::request::layout as request_layout;
use topo::protocol::connection::response::layout as response_layout;
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

#[test]
fn handler_emits_responder_material_response_fact_and_sends_response_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let return_addr = listener.local_addr().expect("listener addr");
    let reader = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept response");
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).expect("read len");
        let mut body = vec![0; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).expect("read body");
        body
    });
    let scenario = synthesize_scenario(SynthOpts {
        request_return_addr: Some(return_addr),
        ..SynthOpts::default()
    });
    let store = test_store();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&scenario.endpoint))
        .expect("seed local endpoint");
    let handler = CreateConnectionResponseHandler::new();
    let context = HandlerContext::with_facts([
        scenario.request_fact.clone(),
        scenario.invite_fact.clone(),
        scenario.receive_fact.clone(),
    ])
    .with_store(&store);

    let output = handler
        .handle(&scenario.intent, &context)
        .expect("handler produces response fact");

    assert_eq!(output.facts.len(), 2);
    let ephemeral_fact = output
        .facts
        .iter()
        .find(|fact| {
            fact.body().first().copied() == Some(ephemeral_layout::TYPE_CONNECTION_EPHEMERAL_SECRET)
        })
        .expect("responder ephemeral fact");
    let response_fact = output
        .facts
        .iter()
        .find(|fact| {
            fact.body().first().copied() == Some(response_layout::TYPE_CONNECTION_RESPONSE)
        })
        .expect("connection response fact");
    let ephemeral = ephemeral_layout::decode_fact(ephemeral_fact.body()).expect("ephemeral");
    let response = response_layout::decode_fact(response_fact.body()).expect("decode response");

    assert_eq!(ephemeral.owner_endpoint, scenario.responder_endpoint);
    assert_eq!(ephemeral.created_at_ms, scenario.received_at);
    assert_ne!(ephemeral.ephemeral_private_key, [0u8; 32]);
    assert_eq!(
        response.responder_ephemeral_secret_fact_id,
        ephemeral_fact.id
    );
    assert_eq!(
        response.responder_ephemeral_public_key,
        ephemeral.ephemeral_public_key
    );
    assert_eq!(response.request_id, scenario.request_fact.id);
    assert_eq!(response.from_endpoint, scenario.responder_endpoint);
    assert_eq!(response.to_endpoint, scenario.initiator_endpoint);
    assert_ne!(response.handshake_hash, [0u8; 32]);
    assert_ne!(response.connection_secret, [0u8; 32]);
    let sent = reader.join().expect("reader");
    assert_eq!(sent[0], bootstrap::TYPE_SEALED_CONNECTION_RESPONSE);
    assert_ne!(sent, response_fact.bytes);
    assert!(!sent
        .windows(response.connection_secret.len())
        .any(|window| window == response.connection_secret));
    let initiator_endpoint = EndpointFact {
        endpoint: scenario.initiator_endpoint,
        secret: scenario.initiator_secret,
        signing_public_key: crypto::ed25519_public_key(&[111; 32]),
        signing_secret: [111; 32],
    };
    assert_eq!(
        bootstrap::open_connection_response(&sent, &initiator_endpoint)
            .expect("open sealed response"),
        response_fact.bytes
    );
}

#[test]
fn handler_rejects_request_addressed_to_a_different_endpoint() {
    let scenario = synthesize_scenario(SynthOpts {
        request_to_endpoint: Some(crypto::x25519_public_key(&[77u8; 32])),
        request_return_addr: Some("127.0.0.1:41099".parse().expect("addr")),
    });
    let store = test_store();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&scenario.endpoint))
        .expect("seed local endpoint");
    let handler = CreateConnectionResponseHandler::new();
    let context = HandlerContext::with_facts([
        scenario.request_fact.clone(),
        scenario.invite_fact.clone(),
        scenario.receive_fact.clone(),
    ])
    .with_store(&store);

    let err = handler
        .handle(&scenario.intent, &context)
        .expect_err("handler rejects mismatched request");
    assert!(
        err.contains("endpoint does not match request")
            || err.contains("endpoint does not match receive"),
        "unexpected error: {err}"
    );
}

struct Scenario {
    request_fact: Fact,
    invite_fact: Fact,
    receive_fact: Fact,
    intent: topo::core::intents::Intent,
    endpoint: EndpointFact,
    initiator_endpoint: [u8; 32],
    initiator_secret: [u8; 32],
    responder_endpoint: [u8; 32],
    received_at: u64,
}

#[derive(Default)]
struct SynthOpts {
    request_to_endpoint: Option<[u8; 32]>,
    request_return_addr: Option<std::net::SocketAddr>,
}

fn synthesize_scenario(opts: SynthOpts) -> Scenario {
    let initiator_static = [11u8; 32];
    let initiator_endpoint = crypto::x25519_public_key(&initiator_static);
    let responder_static = [22u8; 32];
    let responder_endpoint = crypto::x25519_public_key(&responder_static);
    let initiator_ephemeral_private = [33u8; 32];
    let initiator_ephemeral_public = crypto::x25519_public_key(&initiator_ephemeral_private);

    let bootstrap_secret = [55u8; 32];
    let invite = InviteSecretFact::new(bootstrap_secret)
        .validate()
        .expect("invite is well-formed");
    let invite_fact = Fact::new(
        FactScope::Local,
        100,
        invite_layout::encode_fact(&invite).expect("encode invite"),
    );

    let signing_secret = [66u8; 32];
    let endpoint = EndpointFact {
        endpoint: responder_endpoint,
        secret: responder_static,
        signing_public_key: crypto::ed25519_public_key(&signing_secret),
        signing_secret,
    };

    let mut request = ConnectionRequestFact {
        from_endpoint: initiator_endpoint,
        to_endpoint: opts.request_to_endpoint.unwrap_or(responder_endpoint),
        nonce: [77u8; 32],
        invite_fact_id: [88u8; 32],
        bootstrap_hash: invite.bootstrap_hash,
        invite_signature: [0u8; ED25519_SIGNATURE_BYTES],
        invite_secret_fact_id: invite_fact.id,
        initiator_ephemeral_secret_fact_id: [99u8; 32],
        initiator_ephemeral_public_key: initiator_ephemeral_public,
        from_listen_addr: opts.request_return_addr,
        to_listen_addr: None,
    };
    request.invite_signature = crypto::ed25519_sign(
        &invite.bootstrap_secret,
        &topo::protocol::connection::request::create::invite_signing_transcript(&request)
            .expect("transcript"),
    );
    let request_fact = Fact::new(
        FactScope::Global,
        100,
        request_layout::encode_fact(&request).expect("encode request"),
    );

    let received_at = 1_700_000_333;
    let received = ConnectionFactReceipt {
        received_fact_id: request_fact.id,
        origin_addr: topo::protocol::connection::fact_receipt::fact::OriginAddr::new(
            b"127.0.0.1:41001",
        )
        .expect("origin"),
        local_endpoint_id: request.to_endpoint,
        sender_endpoint_id: request.from_endpoint,
        receive_path: RECEIVE_PATH_CONNECTION_REQUEST,
        connection_id: None,
        request_id: Some(request_fact.id),
        frame_hash: crypto::hash(&request_fact.bytes),
        received_at_local_ms: received_at,
    };
    let receive_fact = Fact::new(
        FactScope::Local,
        received_at,
        received_layout::encode_fact(&received).expect("encode receive"),
    );

    let intent = create_connection_response_intent(CreateConnectionResponse {
        request_id: request_fact.id,
        invite_secret_id: invite_fact.id,
        receive_id: receive_fact.id,
    });

    Scenario {
        request_fact,
        invite_fact,
        receive_fact,
        intent,
        endpoint,
        initiator_endpoint,
        initiator_secret: initiator_static,
        responder_endpoint,
        received_at,
    }
}

fn test_store() -> Store {
    Store::open_memory_with_schema_sources(&[
        CORE_SCHEMA_SOURCE,
        network::SCHEMA_SOURCE,
        FACTS_SCHEMA_SOURCE,
    ])
    .expect("store")
}

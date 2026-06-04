//! Behavioural tests for the target `connection::response` handler.
//!
//! The request projector schedules this handler only after exact invite and
//! fact-receipt context exists. The handler rechecks that context,
//! creates local responder ephemeral material, emits response-sent lifecycle
//! state, and leaves network send ownership to that lifecycle fact's projector.

use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, IntentHandler};
use topo::core::network;
use topo::core::projectors::Projector;
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::auth::endpoint::fact::EndpointFact;
use topo::protocol::auth::endpoint::rows as endpoint_rows;
use topo::protocol::auth::invite::fact::InviteSecretFact;
use topo::protocol::auth::invite::layout as invite_layout;
use topo::protocol::connection::bootstrap_request::fact::BootstrapRequestFact;
use topo::protocol::connection::bootstrap_request::layout as request_layout;
use topo::protocol::connection::bootstrap_response::layout as response_layout;
use topo::protocol::connection::bootstrap_response::transit as bootstrap_response;
use topo::protocol::connection::bootstrap_response_sent::layout as response_sent_layout;
use topo::protocol::connection::bootstrap_response_sent::project::BootstrapResponseSentProjector;
use topo::protocol::connection::connection_established::layout as established_layout;
use topo::protocol::connection::create_bootstrap_response::{
    create_bootstrap_response_intent, CreateBootstrapResponse, CreateBootstrapResponseHandler,
};
use topo::protocol::connection::ephemeral_secret::layout as ephemeral_layout;
use topo::protocol::connection::fact_receipt::fact::{
    ConnectionFactReceipt, RECEIVE_PATH_CONNECTION_REQUEST,
};
use topo::protocol::connection::fact_receipt::layout as received_layout;
use topo::protocol::connection::send_network_frame::decode_send_network_frame;
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

#[test]
fn create_handler_emits_responder_material_response_sent_and_established_without_sending() {
    // Flat-intent rule: create_bootstrap_response only creates the responder
    // ephemeral + response facts. It performs no send and chains no intent; the
    // local response projector emits the send once the response fact is admitted.
    let scenario = synthesize_scenario(SynthOpts {
        request_return_addr: Some("127.0.0.1:41099".parse().expect("addr")),
        ..SynthOpts::default()
    });
    let store = test_store();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&scenario.endpoint))
        .expect("seed local endpoint");
    let handler = CreateBootstrapResponseHandler::new();
    let context = HandlerContext::with_facts([
        scenario.request_fact.clone(),
        scenario.invite_fact.clone(),
        scenario.receive_fact.clone(),
    ])
    .with_store(&store);

    let output = handler
        .handle(&scenario.intent, &context)
        .expect("handler produces response fact");

    assert_eq!(output.facts.len(), 3);
    assert!(output.intents.is_empty(), "create handler chains no intent");
    assert!(
        output.local_intents.is_empty(),
        "create handler sends nothing"
    );
    let ephemeral_fact = responder_ephemeral_fact(&output);
    let response_sent_fact = response_sent_fact(&output);
    let established_fact = established_fact(&output);
    let ephemeral = ephemeral_layout::decode_fact(ephemeral_fact.body()).expect("ephemeral");
    let sent =
        response_sent_layout::decode_fact(response_sent_fact.body()).expect("decode response sent");
    let response = sent.response;
    let established =
        established_layout::decode_fact(established_fact.body()).expect("decode established");

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
    assert_eq!(sent.response_id, established.connection_id);
    assert_eq!(established.connection_secret, response.connection_secret);
}

#[test]
fn bootstrap_response_sent_projector_emits_sealed_send_network_frame() {
    let return_addr = "127.0.0.1:41099".parse().expect("addr");
    let scenario = synthesize_scenario(SynthOpts {
        request_return_addr: Some(return_addr),
        ..SynthOpts::default()
    });
    let store = test_store();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&scenario.endpoint))
        .expect("seed local endpoint");

    // Stage one: create the durable responder ephemeral + response facts.
    let create_output = CreateBootstrapResponseHandler::new()
        .handle(
            &scenario.intent,
            &HandlerContext::with_facts([
                scenario.request_fact.clone(),
                scenario.invite_fact.clone(),
                scenario.receive_fact.clone(),
            ])
            .with_store(&store),
        )
        .expect("create response facts");
    let response_sent_fact = response_sent_fact(&create_output).clone();
    let sent =
        response_sent_layout::decode_fact(response_sent_fact.body()).expect("decode response sent");

    let output = BootstrapResponseSentProjector::new()
        .project(
            &response_sent_fact,
            &topo::core::projectors::ProjectionContext::default(),
        )
        .expect("project response_sent");

    assert_eq!(output.effects.local_intents.len(), 1);
    let network_send =
        decode_send_network_frame(&output.effects.local_intents[0]).expect("network send");
    assert_eq!(network_send.routing_key, response_sent_fact.id);
    assert_eq!(
        network_send.frame[0],
        bootstrap_response::TYPE_SEALED_CONNECTION_RESPONSE
    );
    assert!(!network_send
        .frame
        .windows(sent.response.connection_secret.len())
        .any(|window| window == sent.response.connection_secret));
    let initiator_endpoint = EndpointFact {
        endpoint: scenario.initiator_endpoint,
        secret: scenario.initiator_secret,
        signing_public_key: crypto::ed25519_public_key(&[111; 32]),
        signing_secret: [111; 32],
    };
    assert_eq!(
        bootstrap_response::open_connection_response(&network_send.frame, &initiator_endpoint)
            .expect("open sealed response"),
        response_layout::encode_fact(&sent.response).expect("response bytes")
    );
}

fn responder_ephemeral_fact(output: &topo::core::effects::PipelineEffects) -> &Fact {
    output
        .facts
        .iter()
        .find(|fact| {
            fact.body().first().copied() == Some(ephemeral_layout::TYPE_CONNECTION_EPHEMERAL_SECRET)
        })
        .expect("responder ephemeral fact")
}

fn response_sent_fact(output: &topo::core::effects::PipelineEffects) -> &Fact {
    output
        .facts
        .iter()
        .find(|fact| {
            fact.body().first().copied() == Some(response_sent_layout::TYPE_BOOTSTRAP_RESPONSE_SENT)
        })
        .expect("bootstrap response sent fact")
}

fn established_fact(output: &topo::core::effects::PipelineEffects) -> &Fact {
    output
        .facts
        .iter()
        .find(|fact| {
            fact.body().first().copied() == Some(established_layout::TYPE_CONNECTION_ESTABLISHED)
        })
        .expect("connection established fact")
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
    let handler = CreateBootstrapResponseHandler::new();
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

    let mut request = BootstrapRequestFact {
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
        &topo::protocol::connection::bootstrap_request::create::invite_signing_transcript(&request)
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

    let intent = create_bootstrap_response_intent(CreateBootstrapResponse {
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

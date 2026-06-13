//! Behavioural tests for the target `create_connection` handler.

use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, IntentHandler};
use topo::core::network;
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::auth::endpoint as endpoint_rows;
use topo::protocol::auth::endpoint::fact::EndpointFact;
use topo::protocol::auth::invite::encode as invite_layout;
use topo::protocol::auth::invite::fact::InviteSecretFact;
use topo::protocol::connection::connection::project::decode as connection_layout;
use topo::protocol::connection::create_connection::{
    create_connection_intent, CreateConnection, CreateConnectionHandler,
};
use topo::protocol::connection::ephemeral_secret::encode as ephemeral_layout_encode;
use topo::protocol::connection::ephemeral_secret::project::decode as ephemeral_layout_decode;
use topo::protocol::connection::fact_receipt::encode as received_layout;
use topo::protocol::connection::fact_receipt::fact::{
    ConnectionFactReceipt, RECEIVE_PATH_CONNECTION_REQUEST,
};
use topo::protocol::connection::request::encode as request_layout;
use topo::protocol::connection::request::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP};
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

#[test]
fn create_handler_emits_responder_secret_and_sealed_connection() {
    let scenario = synthesize_scenario(SynthOpts {
        request_dialed_addr: Some("127.0.0.1:41099".parse().expect("addr")),
        ..SynthOpts::default()
    });
    let store = test_store();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&scenario.endpoint))
        .expect("seed local endpoint");

    let output = CreateConnectionHandler::new()
        .handle(
            &scenario.intent,
            &HandlerContext::with_facts([
                scenario.request_fact.clone(),
                scenario.invite_fact.clone(),
                scenario.receive_fact.clone(),
            ])
            .with_store(&store),
        )
        .expect("handler produces connection fact");

    assert_eq!(output.facts.len(), 2);
    assert!(output.intents.is_empty(), "create handler chains no intent");
    assert!(
        output.local_intents.is_empty(),
        "create handler sends nothing"
    );

    let ephemeral_fact = output
        .facts
        .iter()
        .find(|fact| {
            fact.body().first().copied()
                == Some(ephemeral_layout_encode::TYPE_CONNECTION_EPHEMERAL_SECRET)
        })
        .expect("responder ephemeral fact");
    let connection_fact = output
        .facts
        .iter()
        .find(|fact| connection_layout::is_sealed_fact(fact.body()))
        .expect("sealed connection fact");
    let ephemeral = ephemeral_layout_decode::decode_fact(ephemeral_fact.body()).expect("ephemeral");
    let connection = connection_layout::open_fact_as_responder(connection_fact.body(), &ephemeral)
        .expect("open connection as responder");

    assert_eq!(ephemeral.owner_endpoint, scenario.responder_endpoint);
    assert_eq!(ephemeral.created_at_ms, scenario.received_at);
    assert_eq!(
        connection.responder_ephemeral_secret_fact_id,
        ephemeral_fact.id
    );
    assert_eq!(
        connection.responder_ephemeral_public_key,
        ephemeral.ephemeral_public_key
    );
    assert_eq!(connection.request_id, scenario.request_fact.id);
    assert_eq!(connection.from_endpoint, scenario.responder_endpoint);
    assert_eq!(connection.to_endpoint, scenario.initiator_endpoint);
    assert_eq!(connection.responder_addr, scenario.request_dialed_addr);
    assert_eq!(
        connection.initiator_addr,
        Some("127.0.0.1:41001".parse().expect("origin addr"))
    );
    assert_ne!(connection.handshake_hash, [0u8; 32]);
    assert_ne!(connection.connection_secret, [0u8; 32]);
}

#[test]
fn handler_rejects_request_addressed_to_a_different_endpoint() {
    let scenario = synthesize_scenario(SynthOpts {
        request_to_endpoint: Some(crypto::x25519_public_key(&[77u8; 32])),
        request_dialed_addr: Some("127.0.0.1:41099".parse().expect("addr")),
    });
    let store = test_store();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&scenario.endpoint))
        .expect("seed local endpoint");

    let err = CreateConnectionHandler::new()
        .handle(
            &scenario.intent,
            &HandlerContext::with_facts([
                scenario.request_fact.clone(),
                scenario.invite_fact.clone(),
                scenario.receive_fact.clone(),
            ])
            .with_store(&store),
        )
        .expect_err("handler rejects mismatched request");
    assert!(
        err.contains("decrypt") || err.contains("endpoint does not match request"),
        "{err}"
    );
}

struct Scenario {
    request_fact: Fact,
    invite_fact: Fact,
    receive_fact: Fact,
    intent: topo::core::intents::Intent,
    endpoint: EndpointFact,
    initiator_endpoint: [u8; 32],
    responder_endpoint: [u8; 32],
    request_dialed_addr: Option<std::net::SocketAddr>,
    received_at: u64,
}

#[derive(Default)]
struct SynthOpts {
    request_to_endpoint: Option<[u8; 32]>,
    request_dialed_addr: Option<std::net::SocketAddr>,
}

fn synthesize_scenario(opts: SynthOpts) -> Scenario {
    let initiator_static = [11u8; 32];
    let initiator_endpoint = crypto::x25519_public_key(&initiator_static);
    let responder_static = [22u8; 32];
    let responder_endpoint = crypto::x25519_public_key(&responder_static);
    let initiator_ephemeral_private = [33u8; 32];
    let initiator_ephemeral_public = crypto::x25519_public_key(&initiator_ephemeral_private);

    let invite = InviteSecretFact::new([55u8; 32])
        .validate()
        .expect("invite is well-formed");
    let invite_fact = Fact::new(
        FactScope::Local,
        100,
        invite_layout::encode_fact(&invite).expect("encode invite"),
    );

    let endpoint = EndpointFact {
        endpoint: responder_endpoint,
        secret: responder_static,
        signing_public_key: crypto::ed25519_public_key(&[66u8; 32]),
        signing_secret: [66u8; 32],
    };

    let mut request = ConnectionRequestFact {
        mode: REQUEST_MODE_BOOTSTRAP,
        from_endpoint: initiator_endpoint,
        to_endpoint: opts.request_to_endpoint.unwrap_or(responder_endpoint),
        nonce: [77u8; 32],
        dialed_addr: opts.request_dialed_addr,
        initiator_addr: None,
        invite_fact_id: [88u8; 32],
        bootstrap_hash: invite.bootstrap_hash,
        invite_secret_fact_id: invite_fact.id,
        invite_signature: [0u8; ED25519_SIGNATURE_BYTES],
        initiator_endpoint_shared_id: [0; 32],
        endpoint_signature: [0u8; ED25519_SIGNATURE_BYTES],
        initiator_ephemeral_secret_fact_id: [99u8; 32],
        initiator_ephemeral_public_key: initiator_ephemeral_public,
    };
    topo::protocol::connection::request::author::sign_bootstrap_request(&mut request, &invite)
        .expect("sign request");
    let request_fact = Fact::new(
        FactScope::Global,
        100,
        request_layout::seal_fact(&request, &initiator_ephemeral_private).expect("seal request"),
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

    let intent = create_connection_intent(CreateConnection {
        request_id: request_fact.id,
        initiator_endpoint_shared_id: invite_fact.id,
        receive_id: receive_fact.id,
    });

    Scenario {
        request_fact,
        invite_fact,
        receive_fact,
        intent,
        endpoint,
        initiator_endpoint,
        responder_endpoint,
        request_dialed_addr: opts.request_dialed_addr,
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

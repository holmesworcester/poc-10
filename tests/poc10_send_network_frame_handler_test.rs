//! SendNetworkFrameHandler wiring tests.
//!
//! Network-send handler wiring tests.

use std::io::Read;
use std::net::TcpListener;
use std::thread;

use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use topo::core::facts::{Fact, FactScope};
use topo::core::intent_pipeline::{retry_intent_reason, HandlerContext, IntentHandler};
use topo::core::network;
use topo::core::schema_dsl::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::facts::connection::request::fact::ConnectionRequestFact;
use topo::protocol::facts::connection::request::layout as connection_request_layout;
use topo::protocol::facts::connection::response::fact::ConnectionResponseFact;
use topo::protocol::facts::connection::response::layout as connection_response_layout;
use topo::protocol::facts::identity::endpoint::fact::EndpointFact;
use topo::protocol::facts::identity::endpoint::rows as endpoint_rows;
use topo::protocol::intents::transport::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame, SendNetworkFrameHandler, SEND_NETWORK_FRAME,
};
use topo::protocol::registry::{FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE};

#[test]
fn well_formed_frame_resolves_route_and_writes_to_tcp_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let reader = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept send");
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).expect("read len");
        let mut body = vec![0; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).expect("read body");
        body
    });
    let store = test_store();
    let local_endpoint = local_endpoint();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&local_endpoint))
        .expect("seed local endpoint");
    let (connection_fact, request_fact) = routed_connection(addr, local_endpoint.endpoint);
    let input = SendNetworkFrame {
        routing_key: connection_fact.id,
        frame: b"opaque-transport::transit-frame-bytes".to_vec(),
    };
    let intent = send_network_frame_intent(input);
    assert_eq!(intent.kind.as_str(), SEND_NETWORK_FRAME);

    let handler = SendNetworkFrameHandler::new();
    let output = handler
        .handle(
            &intent,
            &HandlerContext::with_facts([connection_fact, request_fact]).with_store(&store),
        )
        .expect("network send should write frame");

    assert!(output.facts.is_empty());
    assert!(output.intents.is_empty());
    assert_eq!(
        reader.join().expect("reader"),
        b"opaque-transport::transit-frame-bytes"
    );
}

#[test]
fn empty_frame_is_rejected_before_route_lookup() {
    let intent = send_network_frame_intent(SendNetworkFrame {
        routing_key: [1u8; 32],
        frame: Vec::new(),
    });
    let handler = SendNetworkFrameHandler::new();
    let err = handler
        .handle(&intent, &HandlerContext::new())
        .expect_err("empty frame must be rejected before tcp stop");
    assert!(err.contains("empty"), "{err}");
}

#[test]
fn unreachable_peer_requests_retry_without_consuming_intent() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind closed listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);

    let store = test_store();
    let local_endpoint = local_endpoint();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&local_endpoint))
        .expect("seed local endpoint");
    let (connection_fact, request_fact) = routed_connection(addr, local_endpoint.endpoint);
    let intent = send_network_frame_intent(SendNetworkFrame {
        routing_key: connection_fact.id,
        frame: b"opaque-transport::transit-frame-bytes".to_vec(),
    });

    let err = SendNetworkFrameHandler::new()
        .handle(
            &intent,
            &HandlerContext::with_facts([connection_fact, request_fact]).with_store(&store),
        )
        .expect_err("unreachable peer should request retry");

    assert!(retry_intent_reason(&err).is_some(), "{err}");
    assert!(err.contains("open tcp stream"), "{err}");
}

#[test]
fn missing_route_requests_retry_without_consuming_intent() {
    let store = test_store();
    let local_endpoint = local_endpoint();
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&local_endpoint))
        .expect("seed local endpoint");
    let (connection_fact, request_fact) = connection_without_return_route(local_endpoint.endpoint);
    let intent = send_network_frame_intent(SendNetworkFrame {
        routing_key: connection_fact.id,
        frame: b"opaque-transport::transit-frame-bytes".to_vec(),
    });

    let err = SendNetworkFrameHandler::new()
        .handle(
            &intent,
            &HandlerContext::with_facts([connection_fact, request_fact]).with_store(&store),
        )
        .expect_err("missing route should request retry");

    assert!(retry_intent_reason(&err).is_some(), "{err}");
    assert!(err.contains("send_network_frame route"), "{err}");
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

fn test_store() -> Store {
    Store::open_memory_with_schema_sources_and_schemas(
        &[
            CORE_SCHEMA_SOURCE,
            FACTS_SCHEMA_SOURCE,
            INTENTS_SCHEMA_SOURCE,
        ],
        network::SCHEMAS,
    )
    .expect("store")
}

fn routed_connection(addr: std::net::SocketAddr, local_endpoint: [u8; 32]) -> (Fact, Fact) {
    connection_with_return_route(Some(addr), local_endpoint)
}

fn connection_without_return_route(local_endpoint: [u8; 32]) -> (Fact, Fact) {
    connection_with_return_route(None, local_endpoint)
}

fn connection_with_return_route(
    return_addr: Option<std::net::SocketAddr>,
    local_endpoint: [u8; 32],
) -> (Fact, Fact) {
    let request = ConnectionRequestFact {
        from_endpoint: [10; 32],
        to_endpoint: local_endpoint,
        nonce: [12; 32],
        invite_fact_id: [13; 32],
        bootstrap_hash: [14; 32],
        invite_signature: [15; ED25519_SIGNATURE_BYTES],
        invite_secret_fact_id: [16; 32],
        initiator_ephemeral_secret_fact_id: [17; 32],
        initiator_ephemeral_public_key: [18; 32],
        from_listen_addr: return_addr,
        to_listen_addr: None,
    };
    let request_fact = Fact::new(
        FactScope::Global,
        1,
        connection_request_layout::encode_fact(&request).expect("request"),
    );
    let connection = ConnectionResponseFact {
        from_endpoint: request.to_endpoint,
        to_endpoint: request.from_endpoint,
        request_id: request_fact.id,
        invite_secret_fact_id: request.invite_secret_fact_id,
        initiator_ephemeral_secret_fact_id: request.initiator_ephemeral_secret_fact_id,
        responder_ephemeral_secret_fact_id: [19; 32],
        responder_ephemeral_public_key: [20; 32],
        handshake_hash: [21; 32],
        connection_secret: [22; 32],
    };
    let connection_fact = Fact::new(
        FactScope::Local,
        1,
        connection_response_layout::encode_fact(&connection).expect("response"),
    );
    (connection_fact, request_fact)
}

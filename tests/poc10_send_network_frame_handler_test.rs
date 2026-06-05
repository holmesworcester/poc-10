//! SendNetworkFrameHandler wiring tests.
//!
//! Network-send handler wiring tests.

use std::io::Read;
use std::net::TcpListener;
use std::thread;

use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{retry_intent_reason, HandlerContext, IntentHandler};
use topo::core::network;
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::auth::endpoint as endpoint_rows;
use topo::protocol::auth::endpoint::fact::EndpointFact;
use topo::protocol::connection::connection as connection_rows;
use topo::protocol::connection::connection::encode as connection_layout;
use topo::protocol::connection::connection::fact::ConnectionFact;
use topo::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame, SendNetworkFrameHandler, SEND_NETWORK_FRAME,
};
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

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
    let (connection_fact, connection) = routed_connection(addr, local_endpoint.endpoint);
    seed_connection_route(&store, connection_fact.id, &connection);
    let input = SendNetworkFrame {
        routing_key: connection_fact.id,
        frame: b"opaque-connection::frame-frame-bytes".to_vec(),
    };
    let intent = send_network_frame_intent(input);
    assert_eq!(intent.kind.as_str(), SEND_NETWORK_FRAME);

    let handler = SendNetworkFrameHandler::new();
    let output = handler
        .handle(
            &intent,
            &HandlerContext::with_facts([connection_fact]).with_store(&store),
        )
        .expect("network send should write frame");

    assert!(output.facts.is_empty());
    assert!(output.intents.is_empty());
    assert_eq!(
        reader.join().expect("reader"),
        b"opaque-connection::frame-frame-bytes"
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
    let (connection_fact, connection) = routed_connection(addr, local_endpoint.endpoint);
    seed_connection_route(&store, connection_fact.id, &connection);
    let intent = send_network_frame_intent(SendNetworkFrame {
        routing_key: connection_fact.id,
        frame: b"opaque-connection::frame-frame-bytes".to_vec(),
    });

    let err = SendNetworkFrameHandler::new()
        .handle(
            &intent,
            &HandlerContext::with_facts([connection_fact]).with_store(&store),
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
    let (connection_fact, connection) = connection_without_return_route(local_endpoint.endpoint);
    seed_connection_route(&store, connection_fact.id, &connection);
    let intent = send_network_frame_intent(SendNetworkFrame {
        routing_key: connection_fact.id,
        frame: b"opaque-connection::frame-frame-bytes".to_vec(),
    });

    let err = SendNetworkFrameHandler::new()
        .handle(
            &intent,
            &HandlerContext::with_facts([connection_fact]).with_store(&store),
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
    Store::open_memory_with_schema_sources(&[
        CORE_SCHEMA_SOURCE,
        network::SCHEMA_SOURCE,
        FACTS_SCHEMA_SOURCE,
    ])
    .expect("store")
}

fn routed_connection(
    addr: std::net::SocketAddr,
    local_endpoint: [u8; 32],
) -> (Fact, ConnectionFact) {
    connection_with_return_route(Some(addr), local_endpoint)
}

fn connection_without_return_route(local_endpoint: [u8; 32]) -> (Fact, ConnectionFact) {
    connection_with_return_route(None, local_endpoint)
}

fn connection_with_return_route(
    return_addr: Option<std::net::SocketAddr>,
    local_endpoint: [u8; 32],
) -> (Fact, ConnectionFact) {
    let connection = ConnectionFact {
        from_endpoint: local_endpoint,
        to_endpoint: [10; 32],
        request_id: [11; 32],
        initiator_ephemeral_secret_fact_id: [17; 32],
        responder_ephemeral_secret_fact_id: [19; 32],
        responder_ephemeral_public_key: [20; 32],
        handshake_hash: [21; 32],
        connection_secret: [22; 32],
        responder_addr: None,
        initiator_addr: return_addr,
    };
    let connection_fact = Fact::new(
        FactScope::Local,
        1,
        connection_layout::encode_fact(&connection).expect("connection"),
    );
    (connection_fact, connection)
}

fn seed_connection_route(store: &Store, connection_id: [u8; 32], connection: &ConnectionFact) {
    let rows = vec![
        connection_rows::connection_row(connection_rows::ConnectionRowFields {
            connection_id,
            from_endpoint: connection.from_endpoint,
            to_endpoint: connection.to_endpoint,
            request_id: connection.request_id,
            responder_ephemeral_public_key: connection.responder_ephemeral_public_key,
            handshake_hash: connection.handshake_hash,
            connection_secret: connection.connection_secret,
            responder_addr: connection.responder_addr,
            initiator_addr: connection.initiator_addr,
        })
        .expect("connection row"),
    ];
    store
        .insert_table_rows(rows)
        .expect("seed connection route");
}

//! Tests for the target `send_facts_on_connection` handler.

use topo::core::crypto;
use topo::core::db::Db;
use topo::core::facts::Fact;
use topo::core::intents::{HandlerContext, IntentHandler};
use topo::core::network::{self, NetworkTarget};
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::protocol::auth::endpoint as endpoint_rows;
use topo::protocol::auth::endpoint::fact::EndpointFact;
use topo::protocol::connection::connection as connection_rows;
use topo::protocol::connection::connection::encode as connection_layout;
use topo::protocol::connection::connection::fact::ConnectionFact;
use topo::protocol::connection::frame_small::project as frame_small_project;
use topo::protocol::connection::send_facts_on_connection::SendFactsOnConnectionHandler;
use topo::protocol::connection::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;
use topo::protocol::sync::shared_fact::{encode as shared_fact_layout, fact::SharedFact};

fn connection_fact(
    local_endpoint: [u8; 32],
    peer_addr: std::net::SocketAddr,
) -> (Fact, ConnectionFact) {
    let connection = ConnectionFact {
        from_endpoint: local_endpoint,
        to_endpoint: [11; 32],
        request_id: [12; 32],
        initiator_ephemeral_secret_fact_id: [14; 32],
        responder_ephemeral_secret_fact_id: [15; 32],
        responder_ephemeral_public_key: [16; 32],
        handshake_hash: [17; 32],
        connection_secret: [18; 32],
        responder_addr: None,
        initiator_addr: Some(peer_addr),
    };
    let fact = Fact::new(
        topo::core::facts::FactScope::Local,
        1,
        connection_layout::encode_fact(&connection).expect("connection"),
    );
    (fact, connection)
}

#[test]
fn well_formed_send_intent_packs_fixed_frame_into_outgoing_queue() {
    let store = store_with_local_endpoint();
    let local_endpoint = local_endpoint();
    let peer_addr = "127.0.0.1:41000".parse().expect("peer addr");
    let (connection_fact, connection) = connection_fact(local_endpoint.endpoint, peer_addr);
    store
        .insert_table_values(vec![connection_rows::connection_row(
            connection_rows::ConnectionRowFields {
                connection_id: connection_fact.id,
                from_endpoint: connection.from_endpoint,
                to_endpoint: connection.to_endpoint,
                request_id: connection.request_id,
                responder_ephemeral_public_key: connection.responder_ephemeral_public_key,
                handshake_hash: connection.handshake_hash,
                connection_secret: connection.connection_secret,
                responder_addr: connection.responder_addr,
                initiator_addr: connection.initiator_addr,
            },
        )
        .expect("connection row")])
        .expect("seed connection row");
    let fact = Fact::new(
        topo::protocol::auth::workspace::scope([7; 32]),
        1,
        shared_fact_layout::encode_fact(&SharedFact {
            workspace_id: [7; 32],
            fact_id: [8; 32],
        })
        .expect("encode shared fact"),
    );
    let intent = send_facts_on_connection_intent(SendFactsOnConnection {
        connection_id: connection_fact.id,
        fact_ids: vec![fact.id],
    });

    let handler = SendFactsOnConnectionHandler::new();
    let output = handler
        .handle(
            &intent,
            &HandlerContext::with_facts(&store, [connection_fact.clone(), fact.clone()]),
        )
        .expect("connection::frame packaging succeeds");

    assert!(output.facts.is_empty());
    assert!(output.intents.is_empty());
    assert!(output.local_intents.is_empty());
    let queued = network::claim_outgoing_for_target(&store, NetworkTarget::new(peer_addr), 16)
        .expect("claim outgoing frame");
    assert_eq!(queued.len(), 1);
    let opened =
        frame_small_project::open_connection_frame(&queued[0].bytes, &connection.connection_secret)
            .expect("open fixed connection::frame frame");
    assert_eq!(opened.connection_id, connection_fact.id);
    assert_eq!(opened.sender_endpoint_id, connection.from_endpoint);
    assert_eq!(opened.receiver_endpoint_id, connection.to_endpoint);
    assert_eq!(opened.facts, vec![fact.bytes]);
}

fn store_with_local_endpoint() -> Db {
    let store = Db::open_memory_with_schema_sources(&[
        CORE_SCHEMA_SOURCE,
        network::SCHEMA_SOURCE,
        FACTS_SCHEMA_SOURCE,
    ])
    .expect("store");
    store
        .insert_table_values(vec![
            endpoint_rows::local_endpoint_insert(&local_endpoint()),
        ])
        .expect("seed local endpoint");
    store
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

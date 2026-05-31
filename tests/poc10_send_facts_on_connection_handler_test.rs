//! Tests for the target `send_facts_on_connection` handler.

use topo::core::crypto;
use topo::core::facts::Fact;
use topo::core::intents::{HandlerContext, IntentHandler};
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::auth::endpoint::fact::EndpointFact;
use topo::protocol::auth::endpoint::rows as endpoint_rows;
use topo::protocol::connection::bootstrap_response::fact::BootstrapResponseFact;
use topo::protocol::connection::bootstrap_response::layout as connection_response_layout;
use topo::protocol::connection::send_facts_on_connection::SendFactsOnConnectionHandler;
use topo::protocol::connection::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};
use topo::protocol::connection::send_network_frame;
use topo::protocol::connection_frame_wire as connection_frame;
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;
use topo::protocol::sync::shared_fact::{fact::SharedFact, layout as shared_fact_layout};

fn connection_fact(local_endpoint: [u8; 32]) -> (Fact, BootstrapResponseFact) {
    let connection = BootstrapResponseFact {
        from_endpoint: local_endpoint,
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
        topo::core::facts::FactScope::Local,
        1,
        connection_response_layout::encode_fact(&connection).expect("connection response"),
    );
    (fact, connection)
}

#[test]
fn well_formed_send_intent_packs_fixed_frame_for_send_network_frame() {
    let store = store_with_local_endpoint();
    let local_endpoint = local_endpoint();
    let (connection_fact, connection) = connection_fact(local_endpoint.endpoint);
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
            &HandlerContext::with_facts([connection_fact.clone(), fact.clone()]).with_store(&store),
        )
        .expect("connection::frame packaging succeeds");

    assert!(output.facts.is_empty());
    assert!(output.intents.is_empty());
    assert_eq!(output.local_intents.len(), 1);
    let send = send_network_frame::decode_send_network_frame(&output.local_intents[0])
        .expect("network send");
    assert_eq!(send.routing_key, connection_fact.id);
    let opened =
        connection_frame::open_connection_frame(&send.frame, &connection.connection_secret)
            .expect("open fixed connection::frame frame");
    assert_eq!(opened.connection_id, connection_fact.id);
    assert_eq!(opened.sender_endpoint_id, connection.from_endpoint);
    assert_eq!(opened.receiver_endpoint_id, connection.to_endpoint);
    assert_eq!(
        opened.facts.into_iter().collect::<Vec<_>>(),
        vec![fact.bytes]
    );
}

fn store_with_local_endpoint() -> Store {
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("store");
    store
        .insert_table_rows(endpoint_rows::endpoint_rows(&local_endpoint()))
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

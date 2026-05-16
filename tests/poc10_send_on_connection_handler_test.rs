//! Tests for the target `transit_send_on_connection` handler.

use topo::core::facts::Fact;
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::event_modules::connection_response::fact::ConnectionResponseFact;
use topo::event_modules::connection_response::layout as connection_response_layout;
use topo::event_modules::sync;
use topo::event_modules::transit::frame as transit_frame;
use topo::handlers::network_send;
use topo::handlers::transit::TransitSendOnConnectionHandler;
use topo::handlers::transit::{send_on_connection_intent, TransitSendOnConnection};

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
        topo::core::facts::FactScope::Local,
        1,
        connection_response_layout::encode_fact(&connection).expect("connection response"),
    );
    (fact, connection)
}

#[test]
fn well_formed_send_intent_packs_fixed_frame_for_network_send() {
    let (connection_fact, connection) = connection_fact();
    let fact = Fact::new(
        sync::matchers::workspace_scope([7; 32]),
        1,
        sync::layout::encode_shared_event(&sync::fact::SharedEventFact {
            workspace_id: [7; 32],
            event_id: [8; 32],
        })
        .expect("encode shared event"),
    );
    let intent = send_on_connection_intent(TransitSendOnConnection {
        connection_id: connection_fact.id,
        fact_ids: vec![fact.id],
    });

    let handler = TransitSendOnConnectionHandler::new();
    let output = handler
        .handle(
            &intent,
            &HandlerContext::with_facts([connection_fact.clone(), fact.clone()]),
        )
        .expect("transit packaging succeeds");

    assert!(output.facts.is_empty());
    assert_eq!(output.intents.len(), 1);
    let send = network_send::decode_network_send_frame(&output.intents[0]).expect("network send");
    assert_eq!(send.routing_key, connection_fact.id);
    let opened = transit_frame::open_connection_frame(&send.frame, &connection.connection_secret)
        .expect("open fixed transit frame");
    assert_eq!(opened.connection_id, connection_fact.id);
    assert_eq!(opened.sender_endpoint_id, connection.from_endpoint);
    assert_eq!(opened.receiver_endpoint_id, connection.to_endpoint);
    assert_eq!(
        opened.facts.into_iter().collect::<Vec<_>>(),
        vec![fact.bytes]
    );
}

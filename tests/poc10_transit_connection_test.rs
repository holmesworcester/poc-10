use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::intent_pipeline::{HandlerContext, IntentHandler};
use topo::core::intents::IntentKind;
use topo::core::schema_dsl::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::facts::connection::response::fact::ConnectionResponseFact;
use topo::protocol::facts::connection::response::layout as connection_response_layout;
use topo::protocol::facts::encryption;
use topo::protocol::facts::identity;
use topo::protocol::facts::identity::endpoint::fact::EndpointFact;
use topo::protocol::facts::identity::endpoint::rows as endpoint_rows;
use topo::protocol::facts::sync::shared_fact::{fact::SharedFact, layout as shared_fact_layout};
use topo::protocol::facts::transport::transit::frame as transit_frame;
use topo::protocol::intents::transport::send_facts_on_connection::{
    decode_send_facts_on_connection, send_facts_on_connection_intent, SendFactsOnConnection,
    SendFactsOnConnectionHandler, SEND_FACTS_ON_CONNECTION,
};
use topo::protocol::intents::transport::send_network_frame::{
    decode_send_network_frame, send_network_frame_intent, SendNetworkFrame,
};
use topo::protocol::registry::{FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE};

fn connection_fact() -> (Fact, ConnectionResponseFact) {
    let local_endpoint = local_endpoint();
    let connection = ConnectionResponseFact {
        from_endpoint: local_endpoint.endpoint,
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

#[test]
fn send_facts_on_connection_names_ordered_fact_bundle() {
    let intent = send_facts_on_connection_intent(SendFactsOnConnection {
        connection_id: [9; 32],
        fact_ids: vec![[1; 32], [2; 32], [3; 32]],
    });

    assert_eq!(intent.kind.as_str(), SEND_FACTS_ON_CONNECTION);
    let decoded = decode_send_facts_on_connection(&intent).unwrap();
    assert_eq!(decoded.connection_id, [9; 32]);
    assert_eq!(decoded.fact_ids, vec![[1; 32], [2; 32], [3; 32]]);
}

#[test]
fn send_facts_on_connection_refuses_forged_local_fact_reference() {
    let (connection_fact, _) = connection_fact();
    let fact = Fact::new(
        FactScope::Local,
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
    let context = HandlerContext::with_facts([connection_fact, fact]);

    let err = SendFactsOnConnectionHandler::new()
        .handle(&intent, &context)
        .expect_err("local facts must never be packaged for transport send");

    assert!(
        err.contains("local fact"),
        "error should identify the sendability failure: {err}"
    );
}

#[test]
fn send_facts_on_connection_refuses_forged_private_tag_reference() {
    let (connection_fact, _) = connection_fact();
    for private_tag in [
        identity::signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET,
        encryption::layout::TYPE_LOCAL_KEY_SECRET,
        encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET,
        encryption::layout::TYPE_LOCAL_RECIPIENT_KEY,
    ] {
        let fact = Fact::new(
            topo::protocol::matchers::workspace_scope([7; 32]),
            1,
            vec![private_tag, 1, 2, 3],
        );
        let intent = send_facts_on_connection_intent(SendFactsOnConnection {
            connection_id: connection_fact.id,
            fact_ids: vec![fact.id],
        });
        let context = HandlerContext::with_facts([connection_fact.clone(), fact]);

        let err = SendFactsOnConnectionHandler::new()
            .handle(&intent, &context)
            .expect_err("private/local fact tags must never be packaged for transport send");

        assert!(
            err.contains("private/local fact tag"),
            "tag {private_tag} should be rejected before packaging: {err}"
        );
    }
}

#[test]
fn send_facts_on_connection_accepts_normal_shared_facts() {
    let store = store_with_local_endpoint();
    let (connection_fact, connection) = connection_fact();
    let fact = Fact::new(
        topo::protocol::matchers::workspace_scope([7; 32]),
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
    let context =
        HandlerContext::with_facts([connection_fact.clone(), fact.clone()]).with_store(&store);

    let output = SendFactsOnConnectionHandler::new()
        .handle(&intent, &context)
        .expect("normal shared fact packages for transport");

    assert_eq!(output.intents.len(), 1);
    let send = decode_send_network_frame(&output.intents[0]).unwrap();
    assert_eq!(send.routing_key, connection_fact.id);
    let opened = transit_frame::open_connection_frame(&send.frame, &connection.connection_secret)
        .expect("open packaged transport frame");
    assert_eq!(
        opened.facts.into_iter().collect::<Vec<_>>(),
        vec![fact.bytes]
    );
}

#[test]
fn intent_kind_names_keep_transport_boundaries_clear() {
    for kind in [
        SEND_FACTS_ON_CONNECTION,
        topo::protocol::intents::transport::send_network_frame::SEND_NETWORK_FRAME,
    ] {
        IntentKind::new(kind).expect("intent kind is registry-safe");
    }

    assert!(SEND_FACTS_ON_CONNECTION.starts_with("send_"));
    assert!(
        topo::protocol::intents::transport::send_network_frame::SEND_NETWORK_FRAME
            .starts_with("send_")
    );
}

#[test]
fn idempotence_keys_distinguish_parallel_batches_on_same_route() {
    let first_batch = send_facts_on_connection_intent(SendFactsOnConnection {
        connection_id: [1; 32],
        fact_ids: vec![[2; 32], [3; 32]],
    });
    let first_batch_duplicate =
        send_facts_on_connection_intent(decode_send_facts_on_connection(&first_batch).unwrap());
    let second_batch = send_facts_on_connection_intent(SendFactsOnConnection {
        connection_id: [1; 32],
        fact_ids: vec![[2; 32], [4; 32]],
    });

    assert_eq!(first_batch.key, first_batch_duplicate.key);
    assert_ne!(
        first_batch.key, second_batch.key,
        "same connection may have multiple pending fact bundles"
    );

    let first_frame = send_network_frame_intent(SendNetworkFrame {
        routing_key: [1; 32],
        frame: b"frame:a".to_vec(),
    });
    let second_frame = send_network_frame_intent(SendNetworkFrame {
        routing_key: [1; 32],
        frame: b"frame:b".to_vec(),
    });
    assert_ne!(
        first_frame.key, second_frame.key,
        "same route may have multiple pending frames"
    );
}

fn store_with_local_endpoint() -> Store {
    let store = Store::open_memory_with_schema_sources(&[
        CORE_SCHEMA_SOURCE,
        FACTS_SCHEMA_SOURCE,
        INTENTS_SCHEMA_SOURCE,
    ])
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

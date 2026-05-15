use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::connection_response::fact::ConnectionResponseFact;
use topo::event_modules::connection_response::{layout, project, rows};

fn response_fact() -> ConnectionResponseFact {
    ConnectionResponseFact {
        from_endpoint: [1; 32],
        to_endpoint: [2; 32],
        request_id: [3; 32],
        invite_secret_event_id: [4; 32],
        initiator_ephemeral_secret_event_id: [5; 32],
        responder_ephemeral_secret_event_id: [6; 32],
        responder_ephemeral_public_key: [7; 32],
        handshake_hash: [8; 32],
        connection_secret: [9; 32],
    }
}

#[test]
fn connection_response_projector_materializes_row_through_atomic_intent() {
    let response = response_fact();
    let fact = Fact::new(
        FactScope::Local,
        0,
        layout::encode_fact(&response).expect("encode response"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ConnectionResponseProjector::new(),
            &[],
            &store,
            &[rows::CONNECTION_RESPONSE_ROWS],
            10,
        )
        .expect("project connection response");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::CONNECTION_RESPONSE_ROWS)
        .expect("connection response rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_connection_response_row(&stored[0].0, &stored[0].1)
        .expect("decode connection response row");
    assert_eq!(row.connection_id, fact.id);
    assert_eq!(row.from_endpoint, response.from_endpoint);
    assert_eq!(row.to_endpoint, response.to_endpoint);
    assert_eq!(row.request_id, response.request_id);
    assert_eq!(
        row.responder_ephemeral_public_key,
        response.responder_ephemeral_public_key
    );
    assert_eq!(row.handshake_hash, response.handshake_hash);
    assert_eq!(row.connection_secret, response.connection_secret);
}

#[test]
fn connection_response_projector_rejects_self_loop_endpoints() {
    let mut response = response_fact();
    response.to_endpoint = response.from_endpoint;
    let fact = Fact::new(
        FactScope::Local,
        0,
        layout::encode_fact(&response).expect("encode response"),
    );
    let mut bus = EventBus::new();
    assert!(bus.submit_fact(fact));
    let err = bus
        .drain(&project::ConnectionResponseProjector::new(), &[], 10)
        .expect_err("self-loop endpoints must fail projection");
    assert!(err.contains("endpoints"), "{err}");
}

#[test]
fn connection_response_projector_rejects_malformed_bytes() {
    let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
    let mut bus = EventBus::new();
    assert!(bus.submit_fact(fact));
    let err = bus
        .drain(&project::ConnectionResponseProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(err.contains("connection response") || err.contains("Length"), "{err}");
}

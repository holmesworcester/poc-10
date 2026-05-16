use topo::core::crypto::ED25519_SIGNATURE_BYTES;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::connection_request::fact::ConnectionRequestFact;
use topo::event_modules::connection_request::{layout, project, rows};

fn request_fact() -> ConnectionRequestFact {
    ConnectionRequestFact {
        from_endpoint: [1; 32],
        to_endpoint: [2; 32],
        nonce: [3; 32],
        invite_event_id: [4; 32],
        bootstrap_hash: [5; 32],
        invite_signature: [6; ED25519_SIGNATURE_BYTES],
        invite_secret_event_id: [7; 32],
        initiator_ephemeral_secret_event_id: [8; 32],
        initiator_ephemeral_public_key: [9; 32],
        from_listen_addr: None,
    }
}

#[test]
fn connection_request_projector_materializes_row_through_atomic_intent() {
    let request = request_fact();
    let fact = Fact::new(
        FactScope::Local,
        0,
        layout::encode_fact(&request).expect("encode request"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ConnectionRequestProjector::new(),
            &[],
            &store,
            &[rows::CONNECTION_REQUEST_ROWS],
            10,
        )
        .expect("project connection request");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::CONNECTION_REQUEST_ROWS)
        .expect("connection request rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_connection_request_row(&stored[0].0, &stored[0].1)
        .expect("decode connection request row");
    assert_eq!(row.request_id, fact.id);
    assert_eq!(row.from_endpoint, request.from_endpoint);
    assert_eq!(row.to_endpoint, request.to_endpoint);
    assert_eq!(row.invite_event_id, request.invite_event_id);
    assert_eq!(row.invite_secret_event_id, request.invite_secret_event_id);
    assert_eq!(
        row.initiator_ephemeral_secret_event_id,
        request.initiator_ephemeral_secret_event_id
    );
}

#[test]
fn connection_request_projector_rejects_self_loop() {
    let mut request = request_fact();
    request.to_endpoint = request.from_endpoint;
    let fact = Fact::new(
        FactScope::Local,
        0,
        layout::encode_fact(&request).expect("encode request"),
    );
    let mut bus = WakeLoop::new();
    assert!(bus.submit_fact(fact));
    let err = bus
        .drain(&project::ConnectionRequestProjector::new(), &[], 10)
        .expect_err("self-loop request must fail projection");
    assert!(err.contains("endpoints"), "{err}");
}

#[test]
fn connection_request_projector_rejects_malformed_bytes() {
    let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
    let mut bus = WakeLoop::new();
    assert!(bus.submit_fact(fact));
    let err = bus
        .drain(&project::ConnectionRequestProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.contains("connection request") || err.contains("Length"),
        "{err}"
    );
}

use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_endpoint_shared::fact::{EndpointRole, EndpointSharedFact};
use topo::event_modules::identity_endpoint_shared::{layout, project, rows};

fn sample_fact() -> EndpointSharedFact {
    EndpointSharedFact {
        created_at_ms: 77,
        workspace_id: [1; 32],
        user_authority_event_id: [2; 32],
        endpoint_id: [3; 32],
        signing_public_key: [4; 32],
        endpoint_role: EndpointRole::Device,
        device_name: "phone".to_string(),
    }
}

#[test]
fn endpoint_shared_projector_materializes_row_through_atomic_intent() {
    let payload = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::EndpointSharedProjector::new(),
            &[],
            &store,
            &[rows::ENDPOINT_SHARED_ROWS],
            10,
        )
        .expect("project endpoint shared");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::ENDPOINT_SHARED_ROWS)
        .expect("endpoint shared rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_endpoint_shared_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.workspace_id, [1; 32]);
    assert_eq!(row.endpoint_shared_id, fact.id);
    assert_eq!(row.created_at_ms, 77);
    assert_eq!(row.endpoint_id, [3; 32]);
    assert_eq!(row.signing_public_key, [4; 32]);
    assert_eq!(row.endpoint_role, EndpointRole::Device);
    assert_eq!(row.user_authority_event_id, [2; 32]);
    assert_eq!(row.device_name, "phone");

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain_applying_atomic_rows(
            &project::EndpointSharedProjector::new(),
            &[],
            &store,
            &[rows::ENDPOINT_SHARED_ROWS],
            10,
        )
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
}

#[test]
fn endpoint_shared_projector_rejects_local_scope() {
    let payload = sample_fact();
    let fact = Fact::new(
        FactScope::Local,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::EndpointSharedProjector::new(),
            &[],
            &store,
            &[rows::ENDPOINT_SHARED_ROWS],
            10,
        )
        .expect_err("local scope must fail");
    assert!(err.contains("global scope"), "{err}");
}

#[test]
fn endpoint_shared_projector_rejects_empty_endpoint_id() {
    let mut payload = sample_fact();
    payload.endpoint_id = [0; 32];
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::EndpointSharedProjector::new(),
            &[],
            &store,
            &[rows::ENDPOINT_SHARED_ROWS],
            10,
        )
        .expect_err("empty endpoint must fail");
    assert!(err.contains("endpoint_id"), "{err}");
}

#[test]
fn endpoint_shared_projector_rejects_empty_signing_public_key() {
    let mut payload = sample_fact();
    payload.signing_public_key = [0; 32];
    let fact = Fact::new(
        FactScope::Global,
        payload.created_at_ms,
        layout::encode_fact(&payload).expect("encode endpoint shared"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::EndpointSharedProjector::new(),
            &[],
            &store,
            &[rows::ENDPOINT_SHARED_ROWS],
            10,
        )
        .expect_err("empty signing key must fail");
    assert!(err.contains("signing_public_key"), "{err}");
}

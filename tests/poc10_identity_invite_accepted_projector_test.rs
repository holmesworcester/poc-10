use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::identity_invite_accepted::fact::InviteAcceptedFact;
use topo::event_modules::identity_invite_accepted::{layout, project, rows};

fn sample_fact() -> InviteAcceptedFact {
    InviteAcceptedFact {
        workspace_id: [1; 32],
        invite_event_id: [2; 32],
        invite_secret_event_id: [3; 32],
        bootstrap_hash: [4; 32],
        accepted_endpoint_id: [5; 32],
    }
}

#[test]
fn invite_accepted_projector_materializes_row_through_atomic_intent() {
    let accepted = sample_fact();
    let fact = Fact::new(
        FactScope::Local,
        1,
        layout::encode_fact(&accepted).expect("encode invite_accepted"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::InviteAcceptedProjector::new(),
            &[],
            &store,
            &[rows::INVITE_ACCEPTED_ROWS],
            10,
        )
        .expect("project invite_accepted");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::INVITE_ACCEPTED_ROWS)
        .expect("invite_accepted rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_invite_accepted_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.accepted_endpoint_id, [5; 32]);
    assert_eq!(row.workspace_id, [1; 32]);
    assert_eq!(row.invite_event_id, [2; 32]);
    assert_eq!(row.invite_accepted_event_id, fact.id);
    assert_eq!(row.invite_secret_event_id, [3; 32]);
    assert_eq!(row.bootstrap_hash, [4; 32]);

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain_applying_atomic_rows(
            &project::InviteAcceptedProjector::new(),
            &[],
            &store,
            &[rows::INVITE_ACCEPTED_ROWS],
            10,
        )
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
}

#[test]
fn invite_accepted_projector_rejects_zero_id_field() {
    let mut accepted = sample_fact();
    accepted.invite_secret_event_id = [0; 32];
    let fact = Fact::new(
        FactScope::Local,
        1,
        layout::encode_fact(&accepted).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::InviteAcceptedProjector::new(),
            &[],
            &store,
            &[rows::INVITE_ACCEPTED_ROWS],
            10,
        )
        .expect_err("zero id must fail");
    assert!(err.contains("empty event id"), "{err}");
}

#[test]
fn invite_accepted_projector_rejects_global_scope() {
    let accepted = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        1,
        layout::encode_fact(&accepted).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::InviteAcceptedProjector::new(),
            &[],
            &store,
            &[rows::INVITE_ACCEPTED_ROWS],
            10,
        )
        .expect_err("global scope must fail");
    assert!(err.contains("local scope"), "{err}");
}

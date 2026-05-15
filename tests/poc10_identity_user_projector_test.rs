use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::identity_user::fact::UserFact;
use topo::event_modules::identity_user::{layout, project, rows};

#[test]
fn user_projector_materializes_row_through_atomic_intent() {
    let user = UserFact {
        created_at_ms: 100,
        workspace_id: [2; 32],
        public_key: [7; 32],
        username: "alice".to_string(),
    };
    let fact = Fact::new(
        FactScope::Global,
        user.created_at_ms,
        layout::encode_fact(&user).expect("encode user"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::UserProjector::new(),
            &[],
            &store,
            &[rows::USER_ROWS],
            10,
        )
        .expect("project user");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store.table_rows(rows::USER_ROWS).expect("user rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_user_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.workspace_id, [2; 32]);
    assert_eq!(row.user_id, fact.id);
    assert_eq!(row.username, "alice");
    assert_eq!(row.public_key, [7; 32]);
    assert_eq!(row.user_invite_id, [0; 32]);

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain_applying_atomic_rows(
            &project::UserProjector::new(),
            &[],
            &store,
            &[rows::USER_ROWS],
            10,
        )
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
}

#[test]
fn user_projector_rejects_blank_username() {
    let user = UserFact {
        created_at_ms: 1,
        workspace_id: [2; 32],
        public_key: [7; 32],
        username: "   ".to_string(),
    };
    let fact = Fact::new(
        FactScope::Global,
        user.created_at_ms,
        layout::encode_fact(&user).expect("encode user"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::UserProjector::new(),
            &[],
            &store,
            &[rows::USER_ROWS],
            10,
        )
        .expect_err("blank username must fail");
    assert!(err.contains("username"), "{err}");
}

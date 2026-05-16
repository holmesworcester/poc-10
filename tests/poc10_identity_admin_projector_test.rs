use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_admin::fact::AdminFact;
use topo::event_modules::identity_admin::{layout, project, rows};

#[test]
fn admin_projector_materializes_row_through_atomic_intent() {
    let admin = AdminFact {
        created_at_ms: 200,
        workspace_id: [2; 32],
        public_key: [7; 32],
        authority_fact_id: [2; 32],
        user_fact_id: [2; 32],
    };
    let fact = Fact::new(
        FactScope::Global,
        admin.created_at_ms,
        layout::encode_fact(&admin).expect("encode admin"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::AdminProjector::new(),
            &[],
            &store,
            &[rows::ADMIN_ROWS],
            10,
        )
        .expect("project admin");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store.table_rows(rows::ADMIN_ROWS).expect("admin rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_admin_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.workspace_id, [2; 32]);
    assert_eq!(row.admin_id, fact.id);
    assert_eq!(row.created_at_ms, 200);
    assert_eq!(row.public_key, [7; 32]);
    assert_eq!(row.authority_fact_id, [2; 32]);
    assert_eq!(row.user_fact_id, [2; 32]);

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain_applying_atomic_rows(
            &project::AdminProjector::new(),
            &[],
            &store,
            &[rows::ADMIN_ROWS],
            10,
        )
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
}

#[test]
fn admin_projector_rejects_zero_workspace_id() {
    let admin = AdminFact {
        created_at_ms: 1,
        workspace_id: [0; 32],
        public_key: [7; 32],
        authority_fact_id: [1; 32],
        user_fact_id: [1; 32],
    };
    let fact = Fact::new(
        FactScope::Global,
        admin.created_at_ms,
        layout::encode_fact(&admin).expect("encode admin"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::AdminProjector::new(),
            &[],
            &store,
            &[rows::ADMIN_ROWS],
            10,
        )
        .expect_err("zero workspace_id must fail");
    assert!(err.contains("workspace_id"), "{err}");
}

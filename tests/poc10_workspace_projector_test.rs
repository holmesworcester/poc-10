use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, RowIntentHandler};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::identity_workspace::fact::WorkspaceFact;
use topo::event_modules::identity_workspace::{layout, project};

#[test]
fn workspace_projector_materializes_row_through_atomic_intent() {
    let workspace = WorkspaceFact {
        created_at_ms: 100,
        public_key: [3; 32],
        name: "Research".to_string(),
    };
    let fact = Fact::new(
        FactScope::Global,
        workspace.created_at_ms,
        layout::encode_fact(&workspace).expect("encode workspace"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain(&project::WorkspaceProjector::new(), &[], 10)
        .expect("project workspace");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);

    let handler = RowIntentHandler::new(&store, &[project::WORKSPACE_ROWS]);
    let applied = bus
        .dispatch_intents(&handler, &HandlerContext, 10)
        .expect("apply workspace row intent");

    assert_eq!(applied.handled, 1);
    assert!(bus.intents().is_empty());
    let rows = store
        .table_rows(project::WORKSPACE_ROWS)
        .expect("workspace rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, fact.id);
    assert_eq!(
        layout::decode_row(fact.id, &rows[0].1)
            .expect("decode row")
            .name,
        "Research"
    );

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain(&project::WorkspaceProjector::new(), &[], 10)
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
}

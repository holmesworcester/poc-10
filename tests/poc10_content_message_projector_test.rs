use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::content_message::fact::ContentMessageFact;
use topo::event_modules::content_message::{layout, project, rows};

#[test]
fn content_message_projector_materializes_row_through_atomic_intent() {
    let message = ContentMessageFact {
        workspace_id: [9; 32],
        author_user_id: [22; 32],
        created_at_ms: 180_000,
        frontier_id: [3; 32],
        minute: 3,
        leaf_id: [4; 32],
        sealed_body_ref: [5; 32],
    };
    let fact = Fact::new(
        FactScope::Global,
        message.created_at_ms,
        layout::encode_fact(&message).expect("encode content message"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ContentMessageProjector::new(),
            &[],
            &store,
            &[rows::CONTENT_MESSAGE_ROWS],
            10,
        )
        .expect("project content message");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::CONTENT_MESSAGE_ROWS)
        .expect("content message rows");
    assert_eq!(table.len(), 1);
    let row =
        rows::decode_content_message_row(&table[0].0, &table[0].1).expect("decode message row");
    assert_eq!(row.workspace_id, message.workspace_id);
    assert_eq!(row.message_id, fact.id);
    assert_eq!(row.author_user_id, message.author_user_id);
    assert_eq!(row.created_at_ms, message.created_at_ms);
    assert_eq!(row.frontier_id, message.frontier_id);
    assert_eq!(row.minute, message.minute);
    assert_eq!(row.leaf_id, message.leaf_id);
    assert_eq!(row.sealed_body_ref, message.sealed_body_ref);
}

#[test]
fn content_message_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentMessageProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("message") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

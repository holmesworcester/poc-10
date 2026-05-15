use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::content_event::fact::ContentEventFact;
use topo::event_modules::content_event::{layout, project, rows};

#[test]
fn content_event_projector_materializes_row_through_atomic_intent() {
    let event = ContentEventFact {
        workspace_id: [9; 32],
        timestamp: 12345,
        payload: vec![0; 17],
    };
    let fact = Fact::new(
        FactScope::Global,
        event.timestamp,
        layout::encode_fact(&event).expect("encode content event"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ContentEventProjector::new(),
            &[],
            &store,
            &[rows::CONTENT_EVENT_ROWS],
            10,
        )
        .expect("project content event");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::CONTENT_EVENT_ROWS)
        .expect("content event rows");
    assert_eq!(table.len(), 1);
    let row = rows::decode_content_event_row(&table[0].0, &table[0].1).expect("decode content row");
    assert_eq!(row.workspace_id, event.workspace_id);
    assert_eq!(row.event_id, fact.id);
    assert_eq!(row.timestamp, 12345);
    assert_eq!(row.payload_bytes, 17);
}

#[test]
fn content_event_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 4]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentEventProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(err.contains("content event"), "{err}");
}

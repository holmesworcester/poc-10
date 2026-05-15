use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::sync_have_id::fact::SyncHaveIdFact;
use topo::event_modules::sync_have_id::{layout, project, rows};

fn sample_fact() -> SyncHaveIdFact {
    SyncHaveIdFact {
        connection_id: [4; 32],
        timestamp: 777,
        event_id: [8; 32],
    }
}

#[test]
fn sync_have_id_projector_materializes_row_through_atomic_intent() {
    let event = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        0,
        layout::encode_fact(&event).expect("encode sync have-id"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::SyncHaveIdProjector::new(),
            &[],
            &store,
            &[rows::SYNC_HAVE_ID_ROWS],
            10,
        )
        .expect("project sync have-id");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::SYNC_HAVE_ID_ROWS)
        .expect("sync have-id rows");
    assert_eq!(table.len(), 1);
    let row =
        rows::decode_sync_have_id_row(&table[0].0, &table[0].1).expect("decode sync have-id row");
    assert_eq!(row.connection_id, event.connection_id);
    assert_eq!(row.fact_id, fact.id);
    assert_eq!(row.timestamp, 777);
    assert_eq!(row.event_id, event.event_id);
}

#[test]
fn sync_have_id_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 4]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::SyncHaveIdProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("sync have-id") || err.contains("WrongLength"),
        "{err}"
    );
}

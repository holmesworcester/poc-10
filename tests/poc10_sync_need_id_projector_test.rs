use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::sync_need_id::fact::SyncNeedIdFact;
use topo::event_modules::sync_need_id::{layout, project, rows};

fn sample_fact() -> SyncNeedIdFact {
    SyncNeedIdFact {
        connection_id: [4; 32],
        event_id: [8; 32],
    }
}

#[test]
fn sync_need_id_projector_materializes_row_through_atomic_intent() {
    let event = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        0,
        layout::encode_fact(&event).expect("encode sync need-id"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::SyncNeedIdProjector::new(),
            &[],
            &store,
            &[rows::SYNC_NEED_ID_ROWS],
            10,
        )
        .expect("project sync need-id");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::SYNC_NEED_ID_ROWS)
        .expect("sync need-id rows");
    assert_eq!(table.len(), 1);
    let row =
        rows::decode_sync_need_id_row(&table[0].0, &table[0].1).expect("decode sync need-id row");
    assert_eq!(row.connection_id, event.connection_id);
    assert_eq!(row.fact_id, fact.id);
    assert_eq!(row.event_id, event.event_id);
}

#[test]
fn sync_need_id_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 4]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::SyncNeedIdProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("sync need-id") || err.contains("WrongLength"),
        "{err}"
    );
}

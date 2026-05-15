use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::sync_compare::fact::{RangeSummary, SyncCompareFact, TimestampRange};
use topo::event_modules::sync_compare::{layout, project, rows};

fn sample_fact() -> SyncCompareFact {
    SyncCompareFact {
        connection_id: [4; 32],
        range: TimestampRange {
            start: 100,
            end: 200,
        },
        summary: RangeSummary {
            count: 5,
            fingerprint: [9; 32],
        },
        response_requested: true,
    }
}

#[test]
fn sync_compare_projector_materializes_row_through_atomic_intent() {
    let event = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        0,
        layout::encode_fact(&event).expect("encode sync compare"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::SyncCompareProjector::new(),
            &[],
            &store,
            &[rows::SYNC_COMPARE_ROWS],
            10,
        )
        .expect("project sync compare");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::SYNC_COMPARE_ROWS)
        .expect("sync compare rows");
    assert_eq!(table.len(), 1);
    let row =
        rows::decode_sync_compare_row(&table[0].0, &table[0].1).expect("decode sync compare row");
    assert_eq!(row.connection_id, event.connection_id);
    assert_eq!(row.fact_id, fact.id);
    assert_eq!(row.range_start, 100);
    assert_eq!(row.range_end, 200);
    assert_eq!(row.count, 5);
    assert_eq!(row.fingerprint, [9; 32]);
    assert!(row.response_requested);
}

#[test]
fn sync_compare_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 4]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::SyncCompareProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("sync compare") || err.contains("WrongLength"),
        "{err}"
    );
}

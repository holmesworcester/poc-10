use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::content_file_slice::fact::ContentFileSliceFact;
use topo::event_modules::content_file_slice::{layout, project, rows};

#[test]
fn content_file_slice_projector_materializes_row_through_atomic_intent() {
    let slice = ContentFileSliceFact {
        workspace_id: [9; 32],
        created_at_ms: 4242,
        file_id: [11; 32],
        slice_index: 3,
        ciphertext: vec![0xaa; 128],
    };
    let fact = Fact::new(
        FactScope::Global,
        slice.created_at_ms,
        layout::encode_fact(&slice).expect("encode slice"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ContentFileSliceProjector::new(),
            &[],
            &store,
            &[rows::FILE_SLICE_ROWS],
            10,
        )
        .expect("project slice");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::FILE_SLICE_ROWS)
        .expect("file slice rows");
    assert_eq!(table.len(), 1);
    let row =
        rows::decode_content_file_slice_row(&table[0].0, &table[0].1).expect("decode slice row");
    assert_eq!(row.workspace_id, slice.workspace_id);
    assert_eq!(row.file_id, slice.file_id);
    assert_eq!(row.slice_index, slice.slice_index);
    assert_eq!(row.slice_event_id, fact.id);
    assert_eq!(row.created_at_ms, 4242);
    assert_eq!(row.ciphertext, slice.ciphertext);
}

#[test]
fn content_file_slice_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentFileSliceProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("slice") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

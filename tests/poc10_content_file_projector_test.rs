use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::content_file::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES};
use topo::event_modules::content_file::{layout, project, rows};

#[test]
fn content_file_projector_materializes_row_through_atomic_intent() {
    let file = ContentFileFact {
        workspace_id: [9; 32],
        created_at_ms: 12345,
        message_id: [11; 32],
        author_user_id: [22; 32],
        file_id: [33; 32],
        blob_bytes: 1_048_576,
        total_slices: 4,
        slice_bytes: 262_144,
        root_hash: [44; FILE_ROOT_HASH_BYTES],
        sealed_metadata: b"sealed-filename-and-mime".to_vec(),
    };
    let fact = Fact::new(
        FactScope::Global,
        file.created_at_ms,
        layout::encode_fact(&file).expect("encode file"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ContentFileProjector::new(),
            &[],
            &store,
            &[rows::FILE_ROWS],
            10,
        )
        .expect("project file");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store.table_rows(rows::FILE_ROWS).expect("file rows");
    assert_eq!(table.len(), 1);
    let row = rows::decode_content_file_row(&table[0].0, &table[0].1).expect("decode file row");
    assert_eq!(row.workspace_id, file.workspace_id);
    assert_eq!(row.file_event_id, fact.id);
    assert_eq!(row.created_at_ms, 12345);
    assert_eq!(row.message_id, file.message_id);
    assert_eq!(row.author_user_id, file.author_user_id);
    assert_eq!(row.file_id, file.file_id);
    assert_eq!(row.blob_bytes, file.blob_bytes);
    assert_eq!(row.total_slices, file.total_slices);
    assert_eq!(row.slice_bytes, file.slice_bytes);
    assert_eq!(row.root_hash, file.root_hash);
    assert_eq!(row.sealed_metadata, file.sealed_metadata);
}

#[test]
fn content_file_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentFileProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("file") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

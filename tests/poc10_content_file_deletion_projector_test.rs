use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::content_file_deletion::fact::ContentFileDeletionFact;
use topo::event_modules::content_file_deletion::{layout, project, rows};

#[test]
fn content_file_deletion_projector_materializes_row_through_atomic_intent() {
    let deletion = ContentFileDeletionFact {
        workspace_id: [9; 32],
        created_at_ms: 54321,
        target_file_id: [11; 32],
        author_user_id: [22; 32],
    };
    let fact = Fact::new(
        FactScope::Global,
        deletion.created_at_ms,
        layout::encode_fact(&deletion).expect("encode deletion"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ContentFileDeletionProjector::new(),
            &[],
            &store,
            &[rows::FILE_DELETION_ROWS],
            10,
        )
        .expect("project deletion");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::FILE_DELETION_ROWS)
        .expect("file deletion rows");
    assert_eq!(table.len(), 1);
    let row =
        rows::decode_file_deletion_row(&table[0].0, &table[0].1).expect("decode file deletion row");
    assert_eq!(row.workspace_id, deletion.workspace_id);
    assert_eq!(row.target_file_id, deletion.target_file_id);
    assert_eq!(row.deletion_id, fact.id);
    assert_eq!(row.created_at_ms, 54321);
    assert_eq!(row.author_user_id, deletion.author_user_id);
}

#[test]
fn content_file_deletion_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentFileDeletionProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("deletion") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

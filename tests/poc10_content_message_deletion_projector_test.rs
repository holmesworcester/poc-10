use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::content_message_deletion::fact::ContentMessageDeletionFact;
use topo::event_modules::content_message_deletion::{layout, project, rows};

#[test]
fn content_message_deletion_projector_materializes_row_through_atomic_intent() {
    let deletion = ContentMessageDeletionFact {
        workspace_id: [9; 32],
        created_at_ms: 12345,
        target_message_id: [11; 32],
        author_user_id: [22; 32],
    };
    let fact = Fact::new(
        FactScope::Global,
        deletion.created_at_ms,
        layout::encode_fact(&deletion).expect("encode deletion"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ContentMessageDeletionProjector::new(),
            &[],
            &store,
            &[rows::MESSAGE_DELETION_ROWS],
            10,
        )
        .expect("project deletion");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::MESSAGE_DELETION_ROWS)
        .expect("message deletion rows");
    assert_eq!(table.len(), 1);
    let row = rows::decode_message_deletion_row(&table[0].0, &table[0].1)
        .expect("decode message deletion row");
    assert_eq!(row.workspace_id, deletion.workspace_id);
    assert_eq!(row.target_message_id, deletion.target_message_id);
    assert_eq!(row.deletion_id, fact.id);
    assert_eq!(row.created_at_ms, 12345);
    assert_eq!(row.author_user_id, deletion.author_user_id);
}

#[test]
fn content_message_deletion_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = WakeLoop::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentMessageDeletionProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("deletion") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

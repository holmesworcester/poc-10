use topo::core::facts::{Fact, FactScope};
use topo::core::matchers::ExactSelectorMatcher;
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::content_file::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES};
use topo::event_modules::content_file::{layout as file_layout, matchers as file_context};
use topo::event_modules::content_file_slice::fact::ContentFileSliceFact;
use topo::event_modules::content_file_slice::{layout, project, rows};
use topo::event_modules::content_message::fact::ContentMessageFact;
use topo::event_modules::content_message::{layout as message_layout, matchers as message_context};

#[test]
fn content_file_slice_projector_materializes_row_through_atomic_intent() {
    let parent = ContentMessageFact {
        workspace_id: [9; 32],
        author_user_id: [8; 32],
        created_at_ms: 1000,
        frontier_id: [7; 32],
        minute: 0,
        leaf_id: [6; 32],
        sealed_body_ref: [5; 32],
    };
    let parent_fact = Fact::new(
        message_context::workspace_scope(parent.workspace_id),
        parent.created_at_ms,
        message_layout::encode_fact(&parent).expect("encode parent message"),
    );
    let file = ContentFileFact {
        workspace_id: parent.workspace_id,
        created_at_ms: 1234,
        message_id: parent_fact.id,
        file_id: [11; 32],
        author_user_id: [12; 32],
        blob_bytes: 128,
        total_slices: 4,
        slice_bytes: 32,
        root_hash: [13; FILE_ROOT_HASH_BYTES],
        sealed_metadata: b"sealed".to_vec(),
    };
    let file_fact = Fact::new(
        message_context::workspace_scope(file.workspace_id),
        file.created_at_ms,
        file_layout::encode_fact(&file).expect("encode file"),
    );
    let slice = ContentFileSliceFact {
        workspace_id: [9; 32],
        created_at_ms: 4242,
        file_id: file.file_id,
        slice_index: 3,
        ciphertext: vec![0xaa; 128],
    };
    let fact = Fact::new(
        message_context::workspace_scope(slice.workspace_id),
        slice.created_at_ms,
        layout::encode_fact(&slice).expect("encode slice"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    let message_matcher = ExactSelectorMatcher::new(message_context::message_role());
    let file_matcher = ExactSelectorMatcher::new(file_context::file_role());

    assert!(bus.submit_fact(fact.clone()));
    assert!(bus.submit_fact(parent_fact));
    assert!(bus.submit_fact(file_fact));
    let projected = bus
        .drain_applying_atomic_rows(
            &CombinedProjector,
            &[&message_matcher, &file_matcher],
            &store,
            &[
                rows::FILE_SLICE_ROWS,
                topo::event_modules::content_file::rows::FILE_ROWS,
                topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
            ],
            10,
        )
        .expect("project slice");
    assert_eq!(projected.projections, 5);
    assert_eq!(projected.intents, 3);
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
fn content_file_slice_projector_waits_for_parent_file_context() {
    let slice = ContentFileSliceFact {
        workspace_id: [9; 32],
        created_at_ms: 4242,
        file_id: [11; 32],
        slice_index: 3,
        ciphertext: vec![0xaa; 128],
    };
    let fact = Fact::new(
        message_context::workspace_scope(slice.workspace_id),
        slice.created_at_ms,
        layout::encode_fact(&slice).expect("encode slice"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

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
    assert_eq!(projected.intents, 0);
    let context = bus.context(&fact.id).expect("slice context");
    assert_eq!(context.needs.len(), 1);
    assert_eq!(context.needs[0].role, file_context::file_role());
    assert!(store
        .table_rows(rows::FILE_SLICE_ROWS)
        .expect("slice rows")
        .is_empty());
}

#[test]
fn content_file_slice_file_offer_before_need_wakes_slice() {
    let parent = ContentMessageFact {
        workspace_id: [9; 32],
        author_user_id: [8; 32],
        created_at_ms: 1000,
        frontier_id: [7; 32],
        minute: 0,
        leaf_id: [6; 32],
        sealed_body_ref: [5; 32],
    };
    let parent_fact = Fact::new(
        message_context::workspace_scope(parent.workspace_id),
        parent.created_at_ms,
        message_layout::encode_fact(&parent).expect("encode parent message"),
    );
    let file = ContentFileFact {
        workspace_id: parent.workspace_id,
        created_at_ms: 1234,
        message_id: parent_fact.id,
        file_id: [11; 32],
        author_user_id: [12; 32],
        blob_bytes: 128,
        total_slices: 4,
        slice_bytes: 32,
        root_hash: [13; FILE_ROOT_HASH_BYTES],
        sealed_metadata: b"sealed".to_vec(),
    };
    let file_fact = Fact::new(
        message_context::workspace_scope(file.workspace_id),
        file.created_at_ms,
        file_layout::encode_fact(&file).expect("encode file"),
    );
    let slice = ContentFileSliceFact {
        workspace_id: [9; 32],
        created_at_ms: 4242,
        file_id: file.file_id,
        slice_index: 3,
        ciphertext: vec![0xaa; 128],
    };
    let fact = Fact::new(
        message_context::workspace_scope(slice.workspace_id),
        slice.created_at_ms,
        layout::encode_fact(&slice).expect("encode slice"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();
    let message_matcher = ExactSelectorMatcher::new(message_context::message_role());
    let file_matcher = ExactSelectorMatcher::new(file_context::file_role());

    assert!(bus.submit_fact(parent_fact));
    assert!(bus.submit_fact(file_fact));
    bus.drain_applying_atomic_rows(
        &CombinedProjector,
        &[&message_matcher, &file_matcher],
        &store,
        &[
            rows::FILE_SLICE_ROWS,
            topo::event_modules::content_file::rows::FILE_ROWS,
            topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
        ],
        10,
    )
    .expect("project file first");

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &CombinedProjector,
            &[&message_matcher, &file_matcher],
            &store,
            &[
                rows::FILE_SLICE_ROWS,
                topo::event_modules::content_file::rows::FILE_ROWS,
                topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
            ],
            10,
        )
        .expect("file offer wakes slice need");

    assert_eq!(projected.projections, 2);
    assert_eq!(projected.intents, 1);
    let table = store
        .table_rows(rows::FILE_SLICE_ROWS)
        .expect("file slice rows");
    assert_eq!(table.len(), 1);
    let row =
        rows::decode_content_file_slice_row(&table[0].0, &table[0].1).expect("decode slice row");
    assert_eq!(row.slice_event_id, fact.id);
}

#[test]
fn content_file_slice_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = WakeLoop::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentFileSliceProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("slice") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

struct CombinedProjector;

impl Projector for CombinedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(message_layout::TYPE_CONTENT_MESSAGE) => {
                topo::event_modules::content_message::project::ContentMessageProjector::new()
                    .project(fact, context)
            }
            Some(file_layout::TYPE_CONTENT_FILE) => {
                topo::event_modules::content_file::project::ContentFileProjector::new()
                    .project(fact, context)
            }
            Some(layout::TYPE_CONTENT_FILE_SLICE) => {
                project::ContentFileSliceProjector::new().project(fact, context)
            }
            _ => Err("unknown combined content file slice test fact".to_string()),
        }
    }
}

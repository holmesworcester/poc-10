use topo::core::facts::{Fact, FactScope};
use topo::core::matchers::ExactSelectorMatcher;
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::content_message::fact::ContentMessageFact;
use topo::event_modules::content_message::matchers as message_context;
use topo::event_modules::content_message::{layout, project, rows};
use topo::event_modules::content_message_deletion::fact::ContentMessageDeletionFact;
use topo::event_modules::content_message_deletion::layout as deletion_layout;
use topo::event_modules::identity_matchers;
use topo::event_modules::identity_user::{fact::UserFact, layout as user_layout};

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
        message_context::workspace_scope(message.workspace_id),
        message.created_at_ms,
        layout::encode_fact(&message).expect("encode content message"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

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
fn content_message_keeps_deletion_watch_and_deletes_when_matched() {
    let author_fact = user_fact([9; 32]);
    let message = ContentMessageFact {
        workspace_id: [9; 32],
        author_user_id: author_fact.id,
        created_at_ms: 180_000,
        frontier_id: [3; 32],
        minute: 3,
        leaf_id: [4; 32],
        sealed_body_ref: [5; 32],
    };
    let fact = Fact::new(
        message_context::workspace_scope(message.workspace_id),
        message.created_at_ms,
        layout::encode_fact(&message).expect("encode content message"),
    );
    let deletion = ContentMessageDeletionFact {
        workspace_id: message.workspace_id,
        created_at_ms: message.created_at_ms + 1,
        target_message_id: fact.id,
        author_user_id: message.author_user_id,
    };
    let deletion_fact = Fact::new(
        message_context::workspace_scope(deletion.workspace_id),
        deletion.created_at_ms,
        deletion_layout::encode_fact(&deletion).expect("encode deletion"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let message_matcher = ExactSelectorMatcher::new(message_context::message_role());
    let deletion_matcher = ExactSelectorMatcher::new(message_context::deletion_role());
    let user_matcher = ExactSelectorMatcher::new(identity_matchers::user_role());
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(author_fact));
    assert!(bus.submit_fact(fact.clone()));
    bus.drain_applying_atomic_rows(
        &CombinedProjector,
        &[&message_matcher, &deletion_matcher, &user_matcher],
        &store,
        &[rows::CONTENT_MESSAGE_ROWS],
        10,
    )
    .expect("project message");
    assert_eq!(
        bus.context(&fact.id).expect("message context").needs.len(),
        1
    );
    assert_eq!(
        store
            .table_rows(rows::CONTENT_MESSAGE_ROWS)
            .expect("message rows")
            .len(),
        1
    );

    assert!(bus.submit_fact(deletion_fact));
    let deleted = bus
        .drain_applying_atomic_rows(
            &CombinedProjector,
            &[&message_matcher, &deletion_matcher, &user_matcher],
            &store,
            &[
                rows::CONTENT_MESSAGE_ROWS,
                topo::event_modules::content_message_deletion::rows::MESSAGE_DELETION_ROWS,
            ],
            10,
        )
        .expect("deletion wakes message");

    assert!(deleted.wakes >= 1);
    assert!(bus.context(&fact.id).is_none());
    assert!(store
        .table_rows(rows::CONTENT_MESSAGE_ROWS)
        .expect("message rows")
        .is_empty());
}

#[test]
fn content_message_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = WakeLoop::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentMessageProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("message") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

struct CombinedProjector;

impl topo::core::projection::Projector for CombinedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &topo::core::projection::ProjectionContext,
    ) -> Result<topo::core::projection::ProjectionOutput, String> {
        if deletion_layout::decode_fact(&fact.bytes).is_ok() {
            topo::event_modules::content_message_deletion::project::ContentMessageDeletionProjector::new()
                .project(fact, context)
        } else if layout::decode_fact(&fact.bytes).is_ok() {
            project::ContentMessageProjector::new().project(fact, context)
        } else if user_layout::decode_fact(&fact.bytes).is_ok() {
            Ok(topo::core::projection::ProjectionOutput::new().offer(
                identity_matchers::exact_offer(fact.id, identity_matchers::user_role()),
            ))
        } else {
            Err("unknown combined content message test fact".to_string())
        }
    }
}

fn user_fact(workspace_id: [u8; 32]) -> Fact {
    let user = UserFact {
        created_at_ms: 12_000,
        workspace_id,
        public_key: [22; 32],
        username: "alice".to_string(),
    };
    Fact::new(
        FactScope::Global,
        user.created_at_ms,
        user_layout::encode_fact(&user).expect("encode user"),
    )
}

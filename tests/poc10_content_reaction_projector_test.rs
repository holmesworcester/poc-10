use topo::core::facts::{Fact, FactScope};
use topo::core::matchers::ExactSelectorMatcher;
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::content_message::fact::ContentMessageFact;
use topo::event_modules::content_message::{layout as message_layout, matchers as message_context};
use topo::event_modules::content_reaction::fact::{ContentReactionFact, REACTION_NONCE_BYTES};
use topo::event_modules::content_reaction::{layout, project, rows};

#[test]
fn content_reaction_projector_materializes_row_through_atomic_intent() {
    let mut reaction = ContentReactionFact {
        workspace_id: [9; 32],
        created_at_ms: 12345,
        target_message_id: [11; 32],
        author_user_id: [22; 32],
        nonce: [7; REACTION_NONCE_BYTES],
        ciphertext: b"sealed-emoji".to_vec(),
    };
    let target_message = ContentMessageFact {
        workspace_id: reaction.workspace_id,
        author_user_id: [44; 32],
        created_at_ms: 12_000,
        frontier_id: [55; 32],
        minute: 0,
        leaf_id: [66; 32],
        sealed_body_ref: [77; 32],
    };
    let message_fact = Fact::new(
        message_context::workspace_scope(target_message.workspace_id),
        target_message.created_at_ms,
        message_layout::encode_fact(&target_message).expect("encode message"),
    );
    reaction.target_message_id = message_fact.id;
    let reaction_fact = Fact::new(
        message_context::workspace_scope(reaction.workspace_id),
        reaction.created_at_ms,
        layout::encode_fact(&reaction).expect("encode reaction"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();
    let matcher = ExactSelectorMatcher::new(message_context::message_role());

    assert!(bus.submit_fact(reaction_fact.clone()));
    assert!(bus.submit_fact(message_fact));
    let projected = bus
        .drain_applying_atomic_rows(
            &CombinedProjector,
            &[&matcher],
            &store,
            &[
                rows::REACTION_ROWS,
                topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
            ],
            10,
        )
        .expect("project reaction");
    assert_eq!(projected.projections, 3);
    assert_eq!(projected.intents, 2);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::REACTION_ROWS)
        .expect("reaction rows");
    assert_eq!(table.len(), 1);
    let row = rows::decode_reaction_row(&table[0].0, &table[0].1).expect("decode reaction row");
    assert_eq!(row.workspace_id, reaction.workspace_id);
    assert_eq!(row.reaction_id, reaction_fact.id);
    assert_eq!(row.created_at_ms, 12345);
    assert_eq!(row.target_message_id, reaction.target_message_id);
    assert_eq!(row.author_user_id, reaction.author_user_id);
    assert_eq!(row.nonce, reaction.nonce);
    assert_eq!(row.ciphertext, reaction.ciphertext);
}

#[test]
fn content_reaction_projector_waits_for_target_message_context() {
    let reaction = ContentReactionFact {
        workspace_id: [9; 32],
        created_at_ms: 12345,
        target_message_id: [11; 32],
        author_user_id: [22; 32],
        nonce: [7; REACTION_NONCE_BYTES],
        ciphertext: b"sealed-emoji".to_vec(),
    };
    let fact = Fact::new(
        message_context::workspace_scope(reaction.workspace_id),
        reaction.created_at_ms,
        layout::encode_fact(&reaction).expect("encode reaction"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ContentReactionProjector::new(),
            &[],
            &store,
            &[rows::REACTION_ROWS],
            10,
        )
        .expect("project reaction");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 0);

    let context = bus.context(&fact.id).expect("reaction context");
    assert_eq!(context.needs.len(), 2);
    assert!(context.needs.iter().any(|need| {
        need.role == message_context::message_role()
            && need.selector
                == topo::core::context::Selector::from_bytes(reaction.target_message_id)
    }));
    assert!(context
        .needs
        .iter()
        .any(|need| need.role == message_context::deletion_role()));
    assert!(store
        .table_rows(rows::REACTION_ROWS)
        .expect("reaction rows")
        .is_empty());
}

#[test]
fn content_reaction_target_offer_before_need_wakes_reaction() {
    let mut reaction = ContentReactionFact {
        workspace_id: [9; 32],
        created_at_ms: 12345,
        target_message_id: [11; 32],
        author_user_id: [22; 32],
        nonce: [7; REACTION_NONCE_BYTES],
        ciphertext: b"sealed-emoji".to_vec(),
    };
    let target_message = ContentMessageFact {
        workspace_id: reaction.workspace_id,
        author_user_id: [44; 32],
        created_at_ms: 12_000,
        frontier_id: [55; 32],
        minute: 0,
        leaf_id: [66; 32],
        sealed_body_ref: [77; 32],
    };
    let message_fact = Fact::new(
        message_context::workspace_scope(target_message.workspace_id),
        target_message.created_at_ms,
        message_layout::encode_fact(&target_message).expect("encode message"),
    );
    reaction.target_message_id = message_fact.id;
    let reaction_fact = Fact::new(
        message_context::workspace_scope(reaction.workspace_id),
        reaction.created_at_ms,
        layout::encode_fact(&reaction).expect("encode reaction"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();
    let matcher = ExactSelectorMatcher::new(message_context::message_role());

    assert!(bus.submit_fact(message_fact));
    bus.drain_applying_atomic_rows(
        &CombinedProjector,
        &[&matcher],
        &store,
        &[
            rows::REACTION_ROWS,
            topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
        ],
        10,
    )
    .expect("project target first");

    assert!(bus.submit_fact(reaction_fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &CombinedProjector,
            &[&matcher],
            &store,
            &[
                rows::REACTION_ROWS,
                topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
            ],
            10,
        )
        .expect("target offer wakes reaction need");

    assert_eq!(projected.projections, 2);
    assert_eq!(projected.intents, 1);
    let table = store
        .table_rows(rows::REACTION_ROWS)
        .expect("reaction rows");
    assert_eq!(table.len(), 1);
    let row = rows::decode_reaction_row(&table[0].0, &table[0].1).expect("decode reaction row");
    assert_eq!(row.reaction_id, reaction_fact.id);
}

#[test]
fn content_reaction_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = WakeLoop::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentReactionProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("reaction") || err.to_lowercase().contains("length"),
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
            Some(layout::TYPE_CONTENT_REACTION) => {
                project::ContentReactionProjector::new().project(fact, context)
            }
            _ => Err("unknown combined test fact".to_string()),
        }
    }
}

use topo::core::facts::{Fact, FactScope, ScopeKind};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::event_modules::identity_admin::fact::AdminFact;
use topo::event_modules::identity_admin::layout as admin_layout;
use topo::event_modules::identity_matchers;
use topo::event_modules::removal_frontier::fact::RemovalFrontierFact;
use topo::event_modules::removal_frontier::{layout, project, rows};
use topo::event_modules::sync::matchers as sync_matchers;

fn workspace_scope(workspace_id: [u8; 32]) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("scope kind"),
        id: workspace_id,
    }
}

#[test]
fn removal_frontier_projector_waits_for_authority_and_refs_then_materializes_row() {
    let admin = admin_fact([1; 32], [7; 32]);
    let ref_a = removal_ref_fact([1; 32], 3);
    let ref_b = removal_ref_fact([1; 32], 4);
    let frontier = RemovalFrontierFact {
        workspace_id: [1; 32],
        created_at_ms: 1234,
        authority_admin_id: admin.id,
        removal_fact_ids: vec![ref_a.id, ref_b.id],
    };
    let fact = Fact::new(
        workspace_scope(frontier.workspace_id),
        frontier.created_at_ms,
        layout::encode_fact(&frontier).expect("encode frontier"),
    );
    let projector = project::RemovalFrontierProjector::new();

    let waiting = projector
        .project(&fact, &ProjectionContext::default())
        .expect("missing context waits");
    assert!(waiting.intents.is_empty());
    assert_eq!(waiting.needs.len(), 3);

    let context = ProjectionContext::from_matches(vec![
        matched(
            identity_matchers::exact_need(fact.id, identity_matchers::admin_role(), admin.id),
            identity_matchers::exact_offer(admin.id, identity_matchers::admin_role()),
            admin.clone(),
        ),
        matched(
            sync_matchers::exact_event_need(
                fact.id,
                workspace_scope(frontier.workspace_id),
                ref_a.id,
            ),
            sync_matchers::exact_event_offer(
                ref_a.id,
                workspace_scope(frontier.workspace_id),
                ref_a.id,
                ref_a.id,
            ),
            ref_a.clone(),
        ),
        matched(
            sync_matchers::exact_event_need(
                fact.id,
                workspace_scope(frontier.workspace_id),
                ref_b.id,
            ),
            sync_matchers::exact_event_offer(
                ref_b.id,
                workspace_scope(frontier.workspace_id),
                ref_b.id,
                ref_b.id,
            ),
            ref_b.clone(),
        ),
    ]);
    let projected = projector
        .project(&fact, &context)
        .expect("matched context projects");
    assert_eq!(projected.intents.len(), 1);
    assert_eq!(projected.offers.len(), 1);

    let row = decode_single_put_row(&projected.intents[0]);
    assert_eq!(row.workspace_id, [1; 32]);
    assert_eq!(row.removal_frontier_id, fact.id);
    assert_eq!(row.created_at_ms, 1234);
    assert_eq!(row.authority_admin_id, admin.id);
    assert_eq!(row.removal_fact_ids, vec![ref_a.id, ref_b.id]);
}

#[test]
fn removal_frontier_projector_rejects_scope_mismatch() {
    let frontier = RemovalFrontierFact {
        workspace_id: [1; 32],
        created_at_ms: 1,
        authority_admin_id: [2; 32],
        removal_fact_ids: vec![],
    };
    let fact = Fact::new(
        workspace_scope([9; 32]),
        frontier.created_at_ms,
        layout::encode_fact(&frontier).expect("encode frontier"),
    );
    let err = project::RemovalFrontierProjector::new()
        .project(&fact, &ProjectionContext::default())
        .expect_err("scope mismatch must fail");
    assert!(err.contains("scope"), "{err}");
}

fn admin_fact(workspace_id: [u8; 32], user_fact_id: [u8; 32]) -> Fact {
    Fact::new(
        FactScope::Global,
        1,
        admin_layout::encode_fact(&AdminFact {
            created_at_ms: 1,
            workspace_id,
            public_key: [9; 32],
            authority_fact_id: workspace_id,
            user_fact_id,
        })
        .expect("encode admin"),
    )
}

fn removal_ref_fact(workspace_id: [u8; 32], byte: u8) -> Fact {
    Fact::new(workspace_scope(workspace_id), 1, vec![byte; 32])
}

fn matched(
    need: topo::core::context::ContextNeed,
    offer: topo::core::context::ContextOffer,
    payload: Fact,
) -> MatchedContext {
    MatchedContext {
        need,
        offer,
        payload,
    }
}

fn decode_single_put_row(intent: &topo::core::intents::Intent) -> rows::RemovalFrontierRow {
    match AtomicIntent::from_intent(intent, &[rows::REMOVAL_FRONTIER_ROWS]).expect("row intent") {
        AtomicIntent::PutRow(row) => {
            rows::decode_removal_frontier_row(&row.key, &row.value).expect("decode row")
        }
        AtomicIntent::DeleteRow(_) => panic!("expected put row"),
    }
}

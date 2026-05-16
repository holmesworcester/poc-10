use topo::core::facts::{Fact, FactScope, ScopeKind};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::removal_frontier::fact::RemovalFrontierFact;
use topo::event_modules::removal_frontier::{layout, project, rows};

fn workspace_scope(workspace_id: [u8; 32]) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("scope kind"),
        id: workspace_id,
    }
}

#[test]
fn removal_frontier_projector_materializes_row_through_atomic_intent() {
    let frontier = RemovalFrontierFact {
        workspace_id: [1; 32],
        created_at_ms: 1234,
        authority_admin_id: [2; 32],
        removal_fact_ids: vec![[3; 32], [4; 32]],
    };
    let fact = Fact::new(
        workspace_scope(frontier.workspace_id),
        frontier.created_at_ms,
        layout::encode_fact(&frontier).expect("encode frontier"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::RemovalFrontierProjector::new(),
            &[],
            &store,
            &[rows::REMOVAL_FRONTIER_ROWS],
            10,
        )
        .expect("project frontier");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::REMOVAL_FRONTIER_ROWS)
        .expect("frontier rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_removal_frontier_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.workspace_id, [1; 32]);
    assert_eq!(row.removal_frontier_id, fact.id);
    assert_eq!(row.created_at_ms, 1234);
    assert_eq!(row.authority_admin_id, [2; 32]);
    assert_eq!(row.removal_fact_ids, vec![[3; 32], [4; 32]]);
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
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::RemovalFrontierProjector::new(),
            &[],
            &store,
            &[rows::REMOVAL_FRONTIER_ROWS],
            10,
        )
        .expect_err("scope mismatch must fail");
    assert!(err.contains("scope"), "{err}");
}

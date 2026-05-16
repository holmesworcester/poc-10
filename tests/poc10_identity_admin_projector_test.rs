use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_admin::fact::AdminFact;
use topo::event_modules::identity_admin::{layout, project, rows};
use topo::event_modules::identity_matchers as identity_context;
use topo::event_modules::identity_workspace::{fact::WorkspaceFact, layout as workspace_layout};

#[test]
fn admin_projector_materializes_row_through_atomic_intent() {
    let admin = AdminFact {
        created_at_ms: 200,
        workspace_id: [2; 32],
        public_key: [7; 32],
        authority_fact_id: [2; 32],
        user_fact_id: [2; 32],
    };
    let fact = Fact::new(
        FactScope::Global,
        admin.created_at_ms,
        layout::encode_fact(&admin).expect("encode admin"),
    );
    let workspace_fact = workspace_fact(admin.workspace_id, admin.public_key);
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: identity_context::exact_need(
            fact.id,
            identity_context::workspace_role(),
            workspace_fact.id,
        ),
        offer: identity_context::exact_offer(workspace_fact.id, identity_context::workspace_role()),
        payload: workspace_fact,
    }]);

    let output = project::AdminProjector::new()
        .project(&fact, &context)
        .expect("project admin");
    assert!(output.needs.is_empty());
    assert_eq!(output.intents.len(), 1);
    let row_intent =
        AtomicIntent::from_intent(&output.intents[0], &[rows::ADMIN_ROWS]).expect("row intent");
    let AtomicIntent::PutRow(stored) = row_intent else {
        panic!("expected put row");
    };
    let row = rows::decode_admin_row(&stored.key, &stored.value).expect("decode row");
    assert_eq!(row.workspace_id, [2; 32]);
    assert_eq!(row.admin_id, fact.id);
    assert_eq!(row.created_at_ms, 200);
    assert_eq!(row.public_key, [7; 32]);
    assert_eq!(row.authority_fact_id, [2; 32]);
    assert_eq!(row.user_fact_id, [2; 32]);
}

#[test]
fn admin_projector_waits_for_workspace_context() {
    let admin = AdminFact {
        created_at_ms: 200,
        workspace_id: [2; 32],
        public_key: [7; 32],
        authority_fact_id: [2; 32],
        user_fact_id: [2; 32],
    };
    let fact = Fact::new(
        FactScope::Global,
        admin.created_at_ms,
        layout::encode_fact(&admin).expect("encode admin"),
    );

    let output = project::AdminProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("project waits");

    assert_eq!(output.needs.len(), 1);
    assert!(output.intents.is_empty());
    assert_eq!(output.needs[0].role, identity_context::workspace_role());
    assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
}

fn workspace_fact(workspace_id: [u8; 32], public_key: [u8; 32]) -> Fact {
    Fact {
        id: workspace_id,
        scope: FactScope::Global,
        timestamp: 1,
        bytes: workspace_layout::encode_fact(&WorkspaceFact {
            created_at_ms: 1,
            public_key,
            name: "Workspace".to_string(),
        })
        .expect("encode workspace"),
    }
}

#[test]
fn admin_projector_rejects_zero_workspace_id() {
    let admin = AdminFact {
        created_at_ms: 1,
        workspace_id: [0; 32],
        public_key: [7; 32],
        authority_fact_id: [1; 32],
        user_fact_id: [1; 32],
    };
    let fact = Fact::new(
        FactScope::Global,
        admin.created_at_ms,
        layout::encode_fact(&admin).expect("encode admin"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::AdminProjector::new(),
            &[],
            &store,
            &[rows::ADMIN_ROWS],
            10,
        )
        .expect_err("zero workspace_id must fail");
    assert!(err.contains("workspace_id"), "{err}");
}

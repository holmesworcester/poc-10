use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_invite_server::fact::InviteServerFact;
use topo::event_modules::identity_invite_server::{layout, project, rows};
use topo::event_modules::identity_matchers as identity_context;
use topo::event_modules::identity_workspace::{fact::WorkspaceFact, layout as workspace_layout};

fn sample_fact() -> InviteServerFact {
    InviteServerFact {
        created_at_ms: 9,
        public_key: [1; 32],
        workspace_id: [2; 32],
        authority_event_id: [2; 32],
    }
}

#[test]
fn invite_server_projector_materializes_row_through_atomic_intent() {
    let invite_server = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        invite_server.created_at_ms,
        layout::encode_fact(&invite_server).expect("encode invite_server"),
    );
    let workspace_fact = workspace_fact(invite_server.workspace_id);
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: identity_context::exact_need(
            fact.id,
            identity_context::workspace_role(),
            workspace_fact.id,
        ),
        offer: identity_context::exact_offer(workspace_fact.id, identity_context::workspace_role()),
        payload: workspace_fact,
    }]);

    let output = project::InviteServerProjector::new()
        .project(&fact, &context)
        .expect("project invite_server");
    assert!(output.needs.is_empty());
    assert_eq!(output.intents.len(), 1);
    let row_intent = AtomicIntent::from_intent(&output.intents[0], &[rows::INVITE_SERVER_ROWS])
        .expect("row intent");
    let AtomicIntent::PutRow(stored) = row_intent else {
        panic!("expected put row");
    };
    let row = rows::decode_invite_server_row(&stored.key, &stored.value).expect("decode row");
    assert_eq!(row.workspace_id, [2; 32]);
    assert_eq!(row.invite_server_id, fact.id);
    assert_eq!(row.created_at_ms, 9);
    assert_eq!(row.public_key, [1; 32]);
    assert_eq!(row.authority_event_id, [2; 32]);
}

#[test]
fn invite_server_projector_waits_for_workspace_authority() {
    let invite_server = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        invite_server.created_at_ms,
        layout::encode_fact(&invite_server).expect("encode invite_server"),
    );

    let output = project::InviteServerProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("project waits");

    assert_eq!(output.needs.len(), 1);
    assert!(output.intents.is_empty());
    assert_eq!(output.needs[0].role, identity_context::workspace_role());
    assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
}

fn workspace_fact(workspace_id: [u8; 32]) -> Fact {
    Fact {
        id: workspace_id,
        scope: FactScope::Global,
        timestamp: 1,
        bytes: workspace_layout::encode_fact(&WorkspaceFact {
            created_at_ms: 1,
            public_key: [9; 32],
            name: "Workspace".to_string(),
        })
        .expect("encode workspace"),
    }
}

#[test]
fn invite_server_projector_rejects_empty_authority() {
    let mut invite_server = sample_fact();
    invite_server.authority_event_id = [0; 32];
    let fact = Fact::new(
        FactScope::Global,
        1,
        layout::encode_fact(&invite_server).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::InviteServerProjector::new(),
            &[],
            &store,
            &[rows::INVITE_SERVER_ROWS],
            10,
        )
        .expect_err("empty authority must fail");
    assert!(err.contains("authority"), "{err}");
}

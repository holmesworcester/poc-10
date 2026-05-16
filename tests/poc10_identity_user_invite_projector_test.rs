use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_matchers as identity_context;
use topo::event_modules::identity_user_invite::fact::UserInviteFact;
use topo::event_modules::identity_user_invite::{layout, project, rows};
use topo::event_modules::identity_workspace::{fact::WorkspaceFact, layout as workspace_layout};
use topo::event_modules::identity_workspace::{
    project as workspace_project, rows as workspace_rows,
};

fn sample_fact() -> UserInviteFact {
    UserInviteFact {
        created_at_ms: 5,
        public_key: [1; 32],
        workspace_id: [2; 32],
        authority_event_id: [2; 32],
    }
}

#[test]
fn user_invite_projector_materializes_row_through_atomic_intent() {
    let user_invite = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        user_invite.created_at_ms,
        layout::encode_fact(&user_invite).expect("encode user_invite"),
    );
    let workspace_fact = workspace_fact(user_invite.workspace_id);
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: identity_context::exact_need(
            fact.id,
            identity_context::workspace_role(),
            workspace_fact.id,
        ),
        offer: identity_context::exact_offer(workspace_fact.id, identity_context::workspace_role()),
        payload: workspace_fact,
    }]);

    let output = project::UserInviteProjector::new()
        .project(&fact, &context)
        .expect("project user_invite");
    assert!(output.needs.is_empty());
    assert_eq!(output.intents.len(), 1);
    let row_intent = AtomicIntent::from_intent(&output.intents[0], &[rows::USER_INVITE_ROWS])
        .expect("row intent");
    let AtomicIntent::PutRow(stored) = row_intent else {
        panic!("expected put row");
    };
    let row = rows::decode_user_invite_row(&stored.key, &stored.value).expect("decode row");
    assert_eq!(row.workspace_id, [2; 32]);
    assert_eq!(row.user_invite_id, fact.id);
    assert_eq!(row.created_at_ms, 5);
    assert_eq!(row.public_key, [1; 32]);
    assert_eq!(row.authority_event_id, [2; 32]);
}

#[test]
fn user_invite_projector_waits_for_workspace_authority() {
    let user_invite = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        user_invite.created_at_ms,
        layout::encode_fact(&user_invite).expect("encode user_invite"),
    );

    let output = project::UserInviteProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("project waits");

    assert_eq!(output.needs.len(), 1);
    assert!(output.intents.is_empty());
    assert_eq!(output.needs[0].role, identity_context::workspace_role());
    assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
}

#[test]
fn user_invite_projector_wakes_when_workspace_authority_offer_arrives() {
    let user_invite = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        user_invite.created_at_ms,
        layout::encode_fact(&user_invite).expect("encode user_invite"),
    );
    let workspace_fact = workspace_fact(user_invite.workspace_id);
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let matcher = ExactSelectorMatcher::new(identity_context::workspace_role());
    let matchers = [&matcher as &dyn ContextMatcher];
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let waiting = bus
        .drain_applying_atomic_rows(
            &project::UserInviteProjector::new(),
            &matchers,
            &store,
            &[rows::USER_INVITE_ROWS],
            10,
        )
        .expect("user invite waits");
    assert_eq!(waiting.projections, 1);
    assert_eq!(waiting.intents, 0);

    assert!(bus.submit_fact(workspace_fact));
    let authority = bus
        .drain_applying_atomic_rows(
            &workspace_project::WorkspaceProjector::new(),
            &matchers,
            &store,
            &[workspace_rows::WORKSPACE_ROWS],
            1,
        )
        .expect("workspace projects");
    assert_eq!(authority.wakes, 1);

    let projected = bus
        .drain_applying_atomic_rows(
            &project::UserInviteProjector::new(),
            &matchers,
            &store,
            &[rows::USER_INVITE_ROWS],
            10,
        )
        .expect("user invite reprojects");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
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
fn user_invite_projector_rejects_empty_authority() {
    let mut user_invite = sample_fact();
    user_invite.authority_event_id = [0; 32];
    let fact = Fact::new(
        FactScope::Global,
        1,
        layout::encode_fact(&user_invite).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::UserInviteProjector::new(),
            &[],
            &store,
            &[rows::USER_INVITE_ROWS],
            10,
        )
        .expect_err("empty authority must fail");
    assert!(err.contains("authority"), "{err}");
}

use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_matchers as identity_context;
use topo::event_modules::identity_user::fact::UserFact;
use topo::event_modules::identity_user::{layout, project, rows};
use topo::event_modules::identity_user_invite::{fact::UserInviteFact, layout as invite_layout};

#[test]
fn user_projector_materializes_row_through_atomic_intent() {
    let user = UserFact {
        created_at_ms: 100,
        workspace_id: [2; 32],
        public_key: [7; 32],
        username: "alice".to_string(),
    };
    let fact = Fact::new(
        FactScope::Global,
        user.created_at_ms,
        layout::encode_fact(&user).expect("encode user"),
    );
    let invite_fact = user_invite_fact(user.workspace_id, user.public_key);
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: identity_context::scoped_key_need(
            fact.id,
            identity_context::user_invite_key_role(),
            user.workspace_id,
            user.public_key.to_vec(),
        ),
        offer: identity_context::scoped_key_offer(
            invite_fact.id,
            identity_context::user_invite_key_role(),
            user.workspace_id,
            user.public_key.to_vec(),
        ),
        payload: invite_fact.clone(),
    }]);

    let output = project::UserProjector::new()
        .project(&fact, &context)
        .expect("project user");
    assert!(output.needs.is_empty());
    assert_eq!(output.intents.len(), 1);
    let row_intent =
        AtomicIntent::from_intent(&output.intents[0], &[rows::USER_ROWS]).expect("row intent");
    let AtomicIntent::PutRow(stored) = row_intent else {
        panic!("expected put row");
    };
    let row = rows::decode_user_row(&stored.key, &stored.value).expect("decode row");
    assert_eq!(row.workspace_id, [2; 32]);
    assert_eq!(row.user_id, fact.id);
    assert_eq!(row.username, "alice");
    assert_eq!(row.public_key, [7; 32]);
    assert_eq!(row.user_invite_id, invite_fact.id);
}

#[test]
fn user_projector_waits_for_user_invite_context() {
    let user = UserFact {
        created_at_ms: 100,
        workspace_id: [2; 32],
        public_key: [7; 32],
        username: "alice".to_string(),
    };
    let fact = Fact::new(
        FactScope::Global,
        user.created_at_ms,
        layout::encode_fact(&user).expect("encode user"),
    );

    let output = project::UserProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("project waits");

    assert_eq!(output.needs.len(), 1);
    assert!(output.intents.is_empty());
    assert_eq!(
        output.needs[0].role,
        identity_context::user_invite_key_role()
    );
    assert_eq!(output.needs[0].selector.as_bytes(), &[7; 32]);
}

fn user_invite_fact(workspace_id: [u8; 32], public_key: [u8; 32]) -> Fact {
    let invite = UserInviteFact {
        created_at_ms: 1,
        public_key,
        workspace_id,
        authority_event_id: workspace_id,
    };
    Fact::new(
        FactScope::Global,
        invite.created_at_ms,
        invite_layout::encode_fact(&invite).expect("encode user_invite"),
    )
}

#[test]
fn user_projector_rejects_blank_username() {
    let user = UserFact {
        created_at_ms: 1,
        workspace_id: [2; 32],
        public_key: [7; 32],
        username: "   ".to_string(),
    };
    let fact = Fact::new(
        FactScope::Global,
        user.created_at_ms,
        layout::encode_fact(&user).expect("encode user"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::UserProjector::new(),
            &[],
            &store,
            &[rows::USER_ROWS],
            10,
        )
        .expect_err("blank username must fail");
    assert!(err.contains("username"), "{err}");
}

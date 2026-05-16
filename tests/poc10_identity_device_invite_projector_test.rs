use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_device_invite::fact::DeviceInviteFact;
use topo::event_modules::identity_device_invite::{layout, project, rows};
use topo::event_modules::identity_matchers as identity_context;
use topo::event_modules::identity_user::{fact::UserFact, layout as user_layout};
use topo::event_modules::identity_user_invite::{
    fact::UserInviteFact, layout as user_invite_layout,
};

fn sample_fact() -> DeviceInviteFact {
    DeviceInviteFact {
        created_at_ms: 11,
        workspace_id: [1; 32],
        user_authority_event_id: [2; 32],
        user_invite_event_id: Some([4; 32]),
        public_key: [3; 32],
    }
}

#[test]
fn device_invite_projector_materializes_row_through_atomic_intent() {
    let device_invite = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        device_invite.created_at_ms,
        layout::encode_fact(&device_invite).expect("encode device_invite"),
    );
    let context = device_invite_context(fact.id, &device_invite);

    let output = project::DeviceInviteProjector::new()
        .project(&fact, &context)
        .expect("project device_invite");
    assert!(output.needs.is_empty());
    assert_eq!(output.intents.len(), 1);
    let row_intent = AtomicIntent::from_intent(&output.intents[0], &[rows::DEVICE_INVITE_ROWS])
        .expect("row intent");
    let AtomicIntent::PutRow(stored) = row_intent else {
        panic!("expected put row");
    };
    let row = rows::decode_device_invite_row(&stored.key, &stored.value).expect("decode row");
    assert_eq!(row.workspace_id, [1; 32]);
    assert_eq!(row.device_invite_id, fact.id);
    assert_eq!(row.created_at_ms, 11);
    assert_eq!(row.user_authority_event_id, [2; 32]);
    assert_eq!(row.user_invite_event_id, Some([4; 32]));
    assert_eq!(row.public_key, [3; 32]);
}

#[test]
fn device_invite_projector_waits_for_user_authority() {
    let device_invite = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        device_invite.created_at_ms,
        layout::encode_fact(&device_invite).expect("encode device_invite"),
    );

    let output = project::DeviceInviteProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("project waits");

    assert_eq!(output.needs.len(), 1);
    assert!(output.intents.is_empty());
    assert_eq!(output.needs[0].role, identity_context::user_role());
    assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
}

#[test]
fn device_invite_projector_blocks_endpoint_shared_signed_form_until_signed_context_exists() {
    let device_invite = DeviceInviteFact {
        user_invite_event_id: None,
        ..sample_fact()
    };
    let fact = Fact::new(
        FactScope::Global,
        device_invite.created_at_ms,
        layout::encode_fact(&device_invite).expect("encode"),
    );
    let context = device_invite_context(fact.id, &device_invite);
    let err = project::DeviceInviteProjector::new()
        .project(&fact, &context)
        .expect_err("endpoint_shared-signed form cannot be validated from raw payload");

    assert_eq!(
        err,
        "device_invite endpoint_shared authority requires signed envelope context"
    );
}

#[test]
#[ignore = "blocked: raw device_invite facts do not carry signed envelope signer_event_id or signer_public_key, so the projector cannot identify and verify the authorizing endpoint_shared"]
fn device_invite_endpoint_shared_signed_form_should_project_after_endpoint_context_matches() {
    let device_invite = DeviceInviteFact {
        user_invite_event_id: None,
        ..sample_fact()
    };
    let fact = Fact::new(
        FactScope::Global,
        device_invite.created_at_ms,
        layout::encode_fact(&device_invite).expect("encode"),
    );
    let context = device_invite_context(fact.id, &device_invite);

    let output = project::DeviceInviteProjector::new()
        .project(&fact, &context)
        .expect("future signed-envelope context should authorize endpoint_shared-signed invite");

    assert!(output.needs.is_empty());
    assert_eq!(output.intents.len(), 1);
}

fn device_invite_context(owner: [u8; 32], invite: &DeviceInviteFact) -> ProjectionContext {
    let user_fact = Fact {
        id: invite.user_authority_event_id,
        scope: FactScope::Global,
        timestamp: 1,
        bytes: user_layout::encode_fact(&UserFact {
            created_at_ms: 1,
            workspace_id: invite.workspace_id,
            public_key: [8; 32],
            username: "alice".to_string(),
        })
        .expect("encode user"),
    };
    let mut matches = vec![MatchedContext {
        need: identity_context::exact_need(owner, identity_context::user_role(), user_fact.id),
        offer: identity_context::exact_offer(user_fact.id, identity_context::user_role()),
        payload: user_fact,
    }];
    if let Some(user_invite_id) = invite.user_invite_event_id {
        let user_invite_fact = Fact {
            id: user_invite_id,
            scope: FactScope::Global,
            timestamp: 1,
            bytes: user_invite_layout::encode_fact(&UserInviteFact {
                created_at_ms: 1,
                public_key: [8; 32],
                workspace_id: invite.workspace_id,
                authority_event_id: invite.workspace_id,
            })
            .expect("encode user_invite"),
        };
        matches.push(MatchedContext {
            need: identity_context::exact_need(
                owner,
                identity_context::user_invite_role(),
                user_invite_fact.id,
            ),
            offer: identity_context::exact_offer(
                user_invite_fact.id,
                identity_context::user_invite_role(),
            ),
            payload: user_invite_fact,
        });
    }
    ProjectionContext::from_matches(matches)
}

#[test]
fn device_invite_projector_rejects_empty_user_authority() {
    let mut device_invite = sample_fact();
    device_invite.user_authority_event_id = [0; 32];
    let fact = Fact::new(
        FactScope::Global,
        1,
        layout::encode_fact(&device_invite).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::DeviceInviteProjector::new(),
            &[],
            &store,
            &[rows::DEVICE_INVITE_ROWS],
            10,
        )
        .expect_err("empty user_authority must fail");
    assert!(err.contains("user_authority"), "{err}");
}

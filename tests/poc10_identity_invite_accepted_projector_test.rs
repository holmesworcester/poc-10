use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_invite::{fact::InviteSecretFact, layout as invite_layout};
use topo::event_modules::identity_invite_accepted::fact::InviteAcceptedFact;
use topo::event_modules::identity_invite_accepted::{layout, project, rows};
use topo::event_modules::identity_matchers as identity_context;

fn sample_fact() -> InviteAcceptedFact {
    let secret = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
    InviteAcceptedFact {
        workspace_id: [1; 32],
        invite_event_id: [2; 32],
        invite_secret_event_id: [3; 32],
        bootstrap_hash: secret.bootstrap_hash,
        accepted_endpoint_id: [5; 32],
    }
}

#[test]
fn invite_accepted_projector_materializes_row_through_atomic_intent() {
    let accepted = sample_fact();
    let fact = Fact::new(
        FactScope::Local,
        1,
        layout::encode_fact(&accepted).expect("encode invite_accepted"),
    );
    let secret = InviteSecretFact::scoped([7; 32], [1; 32], [2; 32]);
    let secret_fact = Fact {
        id: accepted.invite_secret_event_id,
        scope: FactScope::Local,
        timestamp: 1,
        bytes: invite_layout::encode_fact(&secret).expect("encode secret"),
    };
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: identity_context::exact_need(
            fact.id,
            identity_context::invite_secret_role(),
            secret_fact.id,
        ),
        offer: identity_context::exact_offer(
            secret_fact.id,
            identity_context::invite_secret_role(),
        ),
        payload: secret_fact,
    }]);

    let output = project::InviteAcceptedProjector::new()
        .project(&fact, &context)
        .expect("project invite_accepted");
    assert!(output.needs.is_empty());
    assert_eq!(output.intents.len(), 1);
    let row_intent = AtomicIntent::from_intent(&output.intents[0], &[rows::INVITE_ACCEPTED_ROWS])
        .expect("row intent");
    let AtomicIntent::PutRow(stored) = row_intent else {
        panic!("expected put row");
    };
    let row = rows::decode_invite_accepted_row(&stored.key, &stored.value).expect("decode row");
    assert_eq!(row.accepted_endpoint_id, [5; 32]);
    assert_eq!(row.workspace_id, [1; 32]);
    assert_eq!(row.invite_event_id, [2; 32]);
    assert_eq!(row.invite_accepted_event_id, fact.id);
    assert_eq!(row.invite_secret_event_id, [3; 32]);
    assert_eq!(row.bootstrap_hash, accepted.bootstrap_hash);
}

#[test]
fn invite_accepted_projector_waits_for_invite_secret_context() {
    let accepted = sample_fact();
    let fact = Fact::new(
        FactScope::Local,
        1,
        layout::encode_fact(&accepted).expect("encode invite_accepted"),
    );

    let output = project::InviteAcceptedProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("project waits");

    assert_eq!(output.needs.len(), 1);
    assert!(output.intents.is_empty());
    assert_eq!(output.needs[0].role, identity_context::invite_secret_role());
    assert_eq!(
        output.needs[0].selector.as_bytes(),
        accepted.invite_secret_event_id
    );
}

#[test]
fn invite_accepted_projector_rejects_zero_id_field() {
    let mut accepted = sample_fact();
    accepted.invite_secret_event_id = [0; 32];
    let fact = Fact::new(
        FactScope::Local,
        1,
        layout::encode_fact(&accepted).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::InviteAcceptedProjector::new(),
            &[],
            &store,
            &[rows::INVITE_ACCEPTED_ROWS],
            10,
        )
        .expect_err("zero id must fail");
    assert!(err.contains("empty event id"), "{err}");
}

#[test]
fn invite_accepted_projector_rejects_global_scope() {
    let accepted = sample_fact();
    let fact = Fact::new(
        FactScope::Global,
        1,
        layout::encode_fact(&accepted).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::InviteAcceptedProjector::new(),
            &[],
            &store,
            &[rows::INVITE_ACCEPTED_ROWS],
            10,
        )
        .expect_err("global scope must fail");
    assert!(err.contains("local scope"), "{err}");
}

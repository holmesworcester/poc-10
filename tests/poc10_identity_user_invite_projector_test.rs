use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::identity_user_invite::fact::UserInviteFact;
use topo::event_modules::identity_user_invite::{layout, project, rows};

fn sample_fact() -> UserInviteFact {
    UserInviteFact {
        created_at_ms: 5,
        public_key: [1; 32],
        workspace_id: [2; 32],
        authority_event_id: [3; 32],
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
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::UserInviteProjector::new(),
            &[],
            &store,
            &[rows::USER_INVITE_ROWS],
            10,
        )
        .expect("project user_invite");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::USER_INVITE_ROWS)
        .expect("user_invite rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_user_invite_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.workspace_id, [2; 32]);
    assert_eq!(row.user_invite_id, fact.id);
    assert_eq!(row.created_at_ms, 5);
    assert_eq!(row.public_key, [1; 32]);
    assert_eq!(row.authority_event_id, [3; 32]);

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain_applying_atomic_rows(
            &project::UserInviteProjector::new(),
            &[],
            &store,
            &[rows::USER_INVITE_ROWS],
            10,
        )
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
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
    let mut bus = EventBus::new();

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

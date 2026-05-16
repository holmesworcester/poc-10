use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::identity_invite_server::fact::InviteServerFact;
use topo::event_modules::identity_invite_server::{layout, project, rows};

fn sample_fact() -> InviteServerFact {
    InviteServerFact {
        created_at_ms: 9,
        public_key: [1; 32],
        workspace_id: [2; 32],
        authority_event_id: [3; 32],
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
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::InviteServerProjector::new(),
            &[],
            &store,
            &[rows::INVITE_SERVER_ROWS],
            10,
        )
        .expect("project invite_server");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::INVITE_SERVER_ROWS)
        .expect("invite_server rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_invite_server_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.workspace_id, [2; 32]);
    assert_eq!(row.invite_server_id, fact.id);
    assert_eq!(row.created_at_ms, 9);
    assert_eq!(row.public_key, [1; 32]);
    assert_eq!(row.authority_event_id, [3; 32]);

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain_applying_atomic_rows(
            &project::InviteServerProjector::new(),
            &[],
            &store,
            &[rows::INVITE_SERVER_ROWS],
            10,
        )
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
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

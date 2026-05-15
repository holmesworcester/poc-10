use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::identity_device_invite::fact::DeviceInviteFact;
use topo::event_modules::identity_device_invite::{layout, project, rows};

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
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::DeviceInviteProjector::new(),
            &[],
            &store,
            &[rows::DEVICE_INVITE_ROWS],
            10,
        )
        .expect("project device_invite");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::DEVICE_INVITE_ROWS)
        .expect("device_invite rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_device_invite_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.workspace_id, [1; 32]);
    assert_eq!(row.device_invite_id, fact.id);
    assert_eq!(row.created_at_ms, 11);
    assert_eq!(row.user_authority_event_id, [2; 32]);
    assert_eq!(row.user_invite_event_id, Some([4; 32]));
    assert_eq!(row.public_key, [3; 32]);

    assert!(!bus.submit_fact(fact));
    let duplicate = bus
        .drain_applying_atomic_rows(
            &project::DeviceInviteProjector::new(),
            &[],
            &store,
            &[rows::DEVICE_INVITE_ROWS],
            10,
        )
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
}

#[test]
fn device_invite_projector_persists_endpoint_shared_signed_without_user_invite() {
    let device_invite = DeviceInviteFact {
        user_invite_event_id: None,
        ..sample_fact()
    };
    let fact = Fact::new(
        FactScope::Global,
        device_invite.created_at_ms,
        layout::encode_fact(&device_invite).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact));
    bus.drain_applying_atomic_rows(
        &project::DeviceInviteProjector::new(),
        &[],
        &store,
        &[rows::DEVICE_INVITE_ROWS],
        10,
    )
    .expect("project device_invite");

    let stored = store
        .table_rows(rows::DEVICE_INVITE_ROWS)
        .expect("rows");
    let row = rows::decode_device_invite_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.user_invite_event_id, None);
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
    let mut bus = EventBus::new();

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

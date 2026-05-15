use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::disappearing_messages_setting::fact::{
    DisappearingMessagesSettingFact, SCOPE_KIND_CHANNEL, SCOPE_KIND_WORKSPACE,
};
use topo::event_modules::disappearing_messages_setting::{layout, project, rows};

fn workspace_setting() -> DisappearingMessagesSettingFact {
    DisappearingMessagesSettingFact {
        workspace_id: [1; 32],
        supersedes_setting_id: None,
        ttl_minutes: 60,
        retire_minute: 12_345,
        scope_kind: SCOPE_KIND_WORKSPACE,
        scope_id: [1; 32],
        author_user_id: [3; 32],
        created_at_ms: 6_000_000,
    }
}

#[test]
fn setting_projector_materializes_row_through_atomic_intent() {
    let setting = workspace_setting();
    let fact = Fact::new(
        FactScope::Global,
        setting.created_at_ms,
        layout::encode_fact(&setting).expect("encode setting"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::DisappearingMessagesSettingProjector::new(),
            &[],
            &store,
            &[rows::DISAPPEARING_MESSAGES_SETTING_ROWS],
            10,
        )
        .expect("project setting");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::DISAPPEARING_MESSAGES_SETTING_ROWS)
        .expect("setting rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_setting_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.workspace_id, setting.workspace_id);
    assert_eq!(row.setting_id, fact.id);
    assert_eq!(row.scope_kind, SCOPE_KIND_WORKSPACE);
    assert_eq!(row.scope_id, setting.workspace_id);
    assert_eq!(row.ttl_minutes, setting.ttl_minutes);
    assert_eq!(row.retire_minute, setting.retire_minute);
    assert_eq!(row.author_user_id, setting.author_user_id);
    assert_eq!(row.supersedes_setting_id, None);
    assert_eq!(row.created_at_ms, setting.created_at_ms);
}

#[test]
fn setting_projector_admits_chained_successor_with_higher_retire_minute() {
    let mut setting = workspace_setting();
    setting.supersedes_setting_id = Some([42; 32]);
    setting.retire_minute = 99_999;
    setting.scope_kind = SCOPE_KIND_CHANNEL;
    setting.scope_id = [9; 32];

    let fact = Fact::new(
        FactScope::Global,
        setting.created_at_ms,
        layout::encode_fact(&setting).expect("encode setting"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    bus.drain_applying_atomic_rows(
        &project::DisappearingMessagesSettingProjector::new(),
        &[],
        &store,
        &[rows::DISAPPEARING_MESSAGES_SETTING_ROWS],
        10,
    )
    .expect("project setting");
    let stored = store
        .table_rows(rows::DISAPPEARING_MESSAGES_SETTING_ROWS)
        .expect("setting rows");
    let row = rows::decode_setting_row(&stored[0].0, &stored[0].1).expect("decode row");
    assert_eq!(row.scope_kind, SCOPE_KIND_CHANNEL);
    assert_eq!(row.scope_id, [9; 32]);
    assert_eq!(row.supersedes_setting_id, Some([42; 32]));
    assert_eq!(row.retire_minute, 99_999);
}

#[test]
fn setting_projector_rejects_zero_ttl() {
    let mut setting = workspace_setting();
    setting.ttl_minutes = 0;
    let fact = Fact::new(
        FactScope::Global,
        setting.created_at_ms,
        layout::encode_fact(&setting).expect("encode setting"),
    );
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(
            &project::DisappearingMessagesSettingProjector::new(),
            &[],
            10,
        )
        .expect_err("zero ttl must fail");
    assert!(err.to_lowercase().contains("ttl"), "{err}");
}

#[test]
fn setting_projector_rejects_workspace_scope_with_mismatched_scope_id() {
    let mut setting = workspace_setting();
    setting.scope_id = [99; 32];
    let fact = Fact::new(
        FactScope::Global,
        setting.created_at_ms,
        layout::encode_fact(&setting).expect("encode setting"),
    );
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(
            &project::DisappearingMessagesSettingProjector::new(),
            &[],
            10,
        )
        .expect_err("workspace-scope mismatch must fail");
    assert!(err.to_lowercase().contains("workspace"), "{err}");
}

#[test]
fn setting_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(
            &project::DisappearingMessagesSettingProjector::new(),
            &[],
            10,
        )
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("setting") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

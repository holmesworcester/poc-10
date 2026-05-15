use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::content_reaction::fact::{ContentReactionFact, REACTION_NONCE_BYTES};
use topo::event_modules::content_reaction::{layout, project, rows};

#[test]
fn content_reaction_projector_materializes_row_through_atomic_intent() {
    let reaction = ContentReactionFact {
        workspace_id: [9; 32],
        created_at_ms: 12345,
        target_message_id: [11; 32],
        author_user_id: [22; 32],
        nonce: [7; REACTION_NONCE_BYTES],
        ciphertext: b"sealed-emoji".to_vec(),
    };
    let fact = Fact::new(
        FactScope::Global,
        reaction.created_at_ms,
        layout::encode_fact(&reaction).expect("encode reaction"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::ContentReactionProjector::new(),
            &[],
            &store,
            &[rows::REACTION_ROWS],
            10,
        )
        .expect("project reaction");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let table = store
        .table_rows(rows::REACTION_ROWS)
        .expect("reaction rows");
    assert_eq!(table.len(), 1);
    let row =
        rows::decode_reaction_row(&table[0].0, &table[0].1).expect("decode reaction row");
    assert_eq!(row.workspace_id, reaction.workspace_id);
    assert_eq!(row.reaction_id, fact.id);
    assert_eq!(row.created_at_ms, 12345);
    assert_eq!(row.target_message_id, reaction.target_message_id);
    assert_eq!(row.author_user_id, reaction.author_user_id);
    assert_eq!(row.nonce, reaction.nonce);
    assert_eq!(row.ciphertext, reaction.ciphertext);
}

#[test]
fn content_reaction_projector_rejects_malformed_fact_bytes() {
    let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
    let mut bus = EventBus::new();
    bus.submit_fact(fact);
    let err = bus
        .drain(&project::ContentReactionProjector::new(), &[], 10)
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.to_lowercase().contains("reaction") || err.to_lowercase().contains("length"),
        "{err}"
    );
}

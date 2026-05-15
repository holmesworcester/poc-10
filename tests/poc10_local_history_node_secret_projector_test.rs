use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::local_history_node_secret::fact::{
    LocalHistoryNodeSecretFact, NODE_SECRET_BYTES, TRIE_LEAF_BIT_DEPTH,
};
use topo::event_modules::local_history_node_secret::{layout, project, rows};

fn minute_node_fact() -> LocalHistoryNodeSecretFact {
    LocalHistoryNodeSecretFact {
        workspace_id: [1; 32],
        removal_frontier_id: [2; 32],
        source_secret_id: [3; 32],
        range_start: 1_700_000,
        range_width: 1,
        bit_depth: 0,
        event_id_prefix: [0; 32],
        tombstone_node_id: [0; 32],
        node_secret: [9; NODE_SECRET_BYTES],
    }
}

#[test]
fn local_history_node_secret_projector_materializes_row_through_atomic_intent() {
    let node = minute_node_fact();
    let fact = Fact::new(FactScope::Local, 1, layout::encode_fact(&node).expect("encode"));
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::LocalHistoryNodeSecretProjector::new(),
            &[],
            &store,
            &[rows::LOCAL_HISTORY_NODE_SECRET_ROWS],
            10,
        )
        .expect("project history node");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());

    let stored = store
        .table_rows(rows::LOCAL_HISTORY_NODE_SECRET_ROWS)
        .expect("history node rows");
    assert_eq!(stored.len(), 1);
    let row = rows::decode_local_history_node_secret_row(&stored[0].0, &stored[0].1)
        .expect("decode row");
    assert_eq!(row.workspace_id, [1; 32]);
    assert_eq!(row.removal_frontier_id, [2; 32]);
    assert_eq!(row.local_history_node_secret_id, fact.id);
    assert_eq!(row.range_start, 1_700_000);
    assert_eq!(row.range_width, 1);
    assert_eq!(row.bit_depth, 0);
    assert_eq!(row.event_id_prefix, [0; 32]);
    assert_eq!(row.node_secret, [9; NODE_SECRET_BYTES]);
}

#[test]
fn local_history_node_secret_projector_rejects_non_local_scope() {
    let node = minute_node_fact();
    let fact = Fact::new(
        FactScope::Global,
        1,
        layout::encode_fact(&node).expect("encode"),
    );
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain_applying_atomic_rows(
            &project::LocalHistoryNodeSecretProjector::new(),
            &[],
            &store,
            &[rows::LOCAL_HISTORY_NODE_SECRET_ROWS],
            10,
        )
        .expect_err("non-local scope must fail");
    assert!(err.contains("Local"), "{err}");
}

#[test]
fn local_history_node_secret_projector_materializes_trie_leaf_row() {
    let leaf = LocalHistoryNodeSecretFact {
        bit_depth: TRIE_LEAF_BIT_DEPTH,
        event_id_prefix: [9; 32],
        node_secret: [7; NODE_SECRET_BYTES],
        ..minute_node_fact()
    };
    let fact = Fact::new(FactScope::Local, 1, layout::encode_fact(&leaf).expect("encode"));
    let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
        .expect("open target schema");
    let mut bus = EventBus::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain_applying_atomic_rows(
            &project::LocalHistoryNodeSecretProjector::new(),
            &[],
            &store,
            &[rows::LOCAL_HISTORY_NODE_SECRET_ROWS],
            10,
        )
        .expect("project leaf");
    assert_eq!(projected.intents, 1);

    let stored = store
        .table_rows(rows::LOCAL_HISTORY_NODE_SECRET_ROWS)
        .expect("rows");
    let row = rows::decode_local_history_node_secret_row(&stored[0].0, &stored[0].1)
        .expect("decode row");
    assert_eq!(row.bit_depth, TRIE_LEAF_BIT_DEPTH);
    assert_eq!(row.event_id_prefix, [9; 32]);
    assert_eq!(row.node_secret, [7; NODE_SECRET_BYTES]);
}

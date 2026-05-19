use topo::core::facts::Fact;
use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::protocol::facts::content;
use topo::protocol::facts::content::message::fact::{
    ContentMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES,
};
use topo::protocol::facts::content::message::rows::{
    content_message_row, opened_message_row, OpenedMessageRow, CONTENT_MESSAGE_ROWS,
    OPENED_MESSAGE_ROWS,
};
use topo::protocol::intents::content::purge_deleted_message::{
    self as purge_intent, PurgeDeletedMessage, PurgeDeletedMessageHandler,
    PURGE_REASON_AUTHOR_DELETION, PURGE_TARGET_MESSAGE,
};
use topo::protocol::matchers::workspace_scope;

const AUTHOR: [u8; 32] = [6; 32];

#[test]
fn purge_deleted_message_missing_target_keeps_intent_queued() {
    let workspace = [1; 32];
    let missing_target = [2; 32];
    let deletion = deletion_fact(workspace, missing_target, AUTHOR);
    let intent = purge_intent(workspace, missing_target, deletion.id);
    let mut bus = WakeLoop::new();

    bus.submit_fact(deletion);
    bus.submit_intent(intent).expect("submit purge intent");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&PurgeDeletedMessageHandler::new(), 10)
        .expect("missing target leaves purge intent queued");

    assert_eq!(report.handled, 0);
    assert_eq!(bus.intents().len(), 1);
}

#[test]
fn purge_deleted_message_missing_proof_keeps_intent_queued() {
    let workspace = [3; 32];
    let message = message_fact(workspace, [4; 32], AUTHOR);
    let intent = purge_intent(workspace, message.id, [5; 32]);
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.submit_intent(intent).expect("submit purge intent");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&PurgeDeletedMessageHandler::new(), 10)
        .expect("missing proof leaves purge intent queued");

    assert_eq!(report.handled, 0);
    assert!(bus.has_fact(&message.id));
    assert_eq!(bus.intents().len(), 1);
}

#[test]
fn purge_deleted_message_with_author_proof_purges_target_fact_and_persists() {
    let workspace = [7; 32];
    let message = message_fact(workspace, [8; 32], AUTHOR);
    let deletion = deletion_fact(workspace, message.id, AUTHOR);
    let intent = purge_intent(workspace, message.id, deletion.id);
    let store =
        Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open core store");
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.submit_fact(deletion.clone());
    bus.submit_intent(intent).expect("submit purge intent");
    assert!(bus
        .intents()
        .iter()
        .any(|intent| intent.kind.as_str() == purge_intent::PURGE_DELETED_MESSAGE));

    let report = bus
        .dispatch_deferred_intents_with_fact_context(&PurgeDeletedMessageHandler::new(), 10)
        .expect("purge target fact");

    assert_eq!(report.handled, 1);
    assert!(!bus.has_fact(&message.id));
    assert!(bus.has_fact(&deletion.id));
    assert!(bus.context(&message.id).is_none());
    assert!(bus
        .intents()
        .iter()
        .all(|intent| intent.kind.as_str() != purge_intent::PURGE_DELETED_MESSAGE));

    bus.save(&store).expect("save purged bus");
    let loaded = WakeLoop::load(&store).expect("load purged bus");
    assert!(!loaded.has_fact(&message.id));
    assert!(loaded.has_fact(&deletion.id));
}

#[test]
fn purge_deleted_message_accepts_content_message_and_content_deletion() {
    let workspace = [9; 32];
    let message = message_fact(workspace, [10; 32], AUTHOR);
    let deletion = deletion_fact(workspace, message.id, AUTHOR);
    let intent = purge_intent(workspace, message.id, deletion.id);
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.submit_fact(deletion.clone());
    bus.submit_intent(intent).expect("submit purge intent");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&PurgeDeletedMessageHandler::new(), 10)
        .expect("purge content message target fact");

    assert_eq!(report.handled, 1);
    assert!(!bus.has_fact(&message.id));
    assert!(bus.has_fact(&deletion.id));
}

#[test]
fn purge_deleted_message_invalid_proof_consumes_without_purge() {
    let workspace = [11; 32];
    let message = message_fact(workspace, [12; 32], AUTHOR);
    let deletion = deletion_fact(workspace, message.id, [13; 32]);
    let intent = purge_intent(workspace, message.id, deletion.id);
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.submit_fact(deletion);
    bus.submit_intent(intent).expect("submit purge intent");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&PurgeDeletedMessageHandler::new(), 10)
        .expect("invalid proof is consumed");

    assert_eq!(report.handled, 1);
    assert!(bus.has_fact(&message.id));
    assert!(bus.intents().is_empty());
}

#[test]
fn purge_deleted_message_handler_does_not_delete_projection_rows() {
    let workspace = [15; 32];
    let signer = [16; 32];
    let message = message_fact(workspace, signer, AUTHOR);
    let deletion = deletion_fact(workspace, message.id, AUTHOR);
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("store");
    let message_body = message_body(workspace, signer, AUTHOR);
    let content_row = content_message_row(message.id, &message_body);
    let opened = opened_message_row(OpenedMessageRow {
        workspace_id: workspace,
        message_id: message.id,
        created_at_ms: 42_000,
        author_user_id: AUTHOR,
        signer_id: signer,
        text: "hello".to_string(),
    });
    store
        .insert_table_rows(vec![content_row.clone(), opened.clone()])
        .expect("seed projection rows");
    let intent = purge_intent(workspace, message.id, deletion.id);
    let mut bus = WakeLoop::new();

    bus.submit_fact(message);
    bus.submit_fact(deletion);
    bus.submit_intent(intent).expect("submit purge intent");
    bus.dispatch_deferred_intents_with_fact_context(&PurgeDeletedMessageHandler::new(), 10)
        .expect("purge fact");

    assert_eq!(
        store
            .table_row(CONTENT_MESSAGE_ROWS, &content_row.key)
            .expect("content message lookup"),
        Some(content_row.value)
    );
    assert_eq!(
        store
            .table_row(OPENED_MESSAGE_ROWS, &opened.key)
            .expect("opened message lookup"),
        Some(opened.value)
    );
}

fn purge_intent(
    workspace_id: [u8; 32],
    target_id: [u8; 32],
    reason_fact_id: [u8; 32],
) -> topo::core::intents::Intent {
    purge_intent::purge_deleted_message_intent(PurgeDeletedMessage {
        workspace_id,
        target_kind: PURGE_TARGET_MESSAGE,
        target_id,
        reason_kind: PURGE_REASON_AUTHOR_DELETION,
        reason_fact_id,
    })
}

fn message_fact(workspace_id: [u8; 32], signer_id: [u8; 32], author_user_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        42,
        content::message::layout::encode_fact(&message_body(
            workspace_id,
            signer_id,
            author_user_id,
        ))
        .expect("encode content message"),
    )
}

fn message_body(
    workspace_id: [u8; 32],
    signer_id: [u8; 32],
    author_user_id: [u8; 32],
) -> ContentMessageFact {
    ContentMessageFact {
        workspace_id,
        created_at_ms: 42_000,
        author_user_id,
        signer_id,
        frontier_id: [17; 32],
        local_history_node_secret_id: [18; 32],
        expires_at_minute: u64::MAX,
        disappearing_setting_id: [19; 32],
        minute: 42,
        leaf_id: [20; 32],
        nonce: [21; NONCE_BYTES],
        ciphertext: vec![0x33; CIPHERTEXT_BYTES.min(4)],
    }
}

fn deletion_fact(workspace_id: [u8; 32], target_id: [u8; 32], author_user_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        43,
        content::message_deletion::layout::encode_fact(
            &content::message_deletion::fact::ContentMessageDeletionFact {
                workspace_id,
                created_at_ms: 43,
                target_message_id: target_id,
                author_user_id,
            },
        )
        .expect("encode content deletion"),
    )
}

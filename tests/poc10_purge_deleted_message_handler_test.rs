use topo::core::facts::Fact;
use topo::core::matchers::ContextMatcher;
use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::protocol::facts::content::sealed_message::fact::{
    MessageDeletionFact, SealedMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES,
};
use topo::protocol::facts::content::sealed_message::intent::{
    self as purge_intent, PurgeDeletedMessage, PURGE_REASON_AUTHOR_DELETION, PURGE_TARGET_MESSAGE,
};
use topo::protocol::facts::content::sealed_message::rows::{
    message_row, sealed_message_row, MessageRow, SealedMessageRow, MESSAGE_ROWS,
    SEALED_MESSAGE_ROWS,
};
use topo::protocol::facts::content::sealed_message::{layout, project};
use topo::protocol::intents::content::purge_deleted_message::PurgeDeletedMessageHandler;
use topo::protocol::matchers::ExactSelectorMatcher;
use topo::protocol::matchers::{self as context, workspace_scope, SecretCoverageMatcher};

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
    let projector = project::SealedMessageProjector::new();
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &deletion_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let store =
        Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open core store");
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.submit_fact(deletion.clone());
    bus.drain(&projector, &matchers, 10)
        .expect("deletion emits purge intent");
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
    let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE]).expect("store");
    let sealed = sealed_message_row(SealedMessageRow {
        workspace_id: workspace,
        message_id: message.id,
        created_at_ms: 42_000,
        author_user_id: AUTHOR,
        signer_id: signer,
        frontier_id: [17; 32],
        local_history_node_secret_id: [18; 32],
        expires_at_minute: u64::MAX,
        disappearing_setting_id: [19; 32],
        minute: 42,
        leaf_id: [20; 32],
        nonce: [21; NONCE_BYTES],
        ciphertext: vec![0x33; CIPHERTEXT_BYTES.min(4)],
    })
    .expect("sealed row");
    let opened = message_row(MessageRow {
        workspace_id: workspace,
        message_id: message.id,
        created_at_ms: 42_000,
        author_user_id: AUTHOR,
        signer_id: signer,
        minute: 42,
        leaf_id: [20; 32],
    });
    store
        .insert_table_rows(vec![sealed.clone(), opened.clone()])
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
            .table_row(SEALED_MESSAGE_ROWS, &sealed.key)
            .expect("sealed lookup"),
        Some(sealed.value)
    );
    assert_eq!(
        store
            .table_row(MESSAGE_ROWS, &opened.key)
            .expect("message lookup"),
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
        layout::encode_sealed_message(&SealedMessageFact {
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
        })
        .expect("encode sealed message"),
    )
}

fn deletion_fact(workspace_id: [u8; 32], target_id: [u8; 32], author_user_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        43,
        layout::encode_message_deletion(&MessageDeletionFact {
            workspace_id,
            target_id,
            author_user_id,
        })
        .expect("encode deletion"),
    )
}

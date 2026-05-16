use topo::core::facts::Fact;
use topo::core::wake_loop::WakeLoop;
use topo::protocol::fact_modules::content_file::fact::ContentFileFact;
use topo::protocol::fact_modules::content_reaction::fact::{
    ContentReactionFact, REACTION_NONCE_BYTES,
};
use topo::protocol::fact_modules::disappearing_messages_setting::fact::{
    DisappearingMessagesSettingFact, SCOPE_KIND_WORKSPACE,
};
use topo::protocol::fact_modules::sealed_message::fact::{
    MessageDeletionFact, SealedMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES,
};
use topo::protocol::fact_modules::{content_file, content_reaction, disappearing_messages_setting};
use topo::protocol::fact_modules::{sealed_message, sealed_message::layout};
use topo::protocol::intent_handlers::purge_cascade::{
    cascade_child_purge_intent, CascadeChildPurge, PurgeCascadeHandler, CASCADE_CHILD_FILE,
    CASCADE_CHILD_REACTION,
};
use topo::protocol::intent_handlers::retention_expiry::{
    expire_message_intent, ExpireMessage, RetentionExpiryHandler,
};
use topo::protocol::intent_handlers::retention_floor::{
    apply_retention_floor_intent, ApplyRetentionFloor, RetentionFloorHandler,
};
use topo::protocol::matchers::workspace_scope;

const WORKSPACE: [u8; 32] = [1; 32];
const AUTHOR: [u8; 32] = [2; 32];

#[test]
fn cascade_purges_reaction_bound_to_deleted_parent_message() {
    let parent_id = [3; 32];
    let deletion = deletion_fact(parent_id);
    let reaction = reaction_fact(parent_id);
    let intent = cascade_child_purge_intent(CascadeChildPurge {
        workspace_id: WORKSPACE,
        parent_message_id: parent_id,
        child_kind: CASCADE_CHILD_REACTION,
        child_id: reaction.id,
        parent_deletion_id: deletion.id,
    });
    let mut bus = WakeLoop::new();

    bus.submit_fact(deletion);
    bus.submit_fact(reaction.clone());
    bus.submit_intent(intent).expect("submit cascade");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&PurgeCascadeHandler::new(), 10)
        .expect("cascade purge");

    assert_eq!(report.handled, 1);
    assert!(!bus.has_fact(&reaction.id));
}

#[test]
fn cascade_purges_file_bound_to_deleted_parent_message() {
    let parent_id = [4; 32];
    let deletion = deletion_fact(parent_id);
    let file = file_fact(parent_id);
    let intent = cascade_child_purge_intent(CascadeChildPurge {
        workspace_id: WORKSPACE,
        parent_message_id: parent_id,
        child_kind: CASCADE_CHILD_FILE,
        child_id: file.id,
        parent_deletion_id: deletion.id,
    });
    let mut bus = WakeLoop::new();

    bus.submit_fact(deletion);
    bus.submit_fact(file.clone());
    bus.submit_intent(intent).expect("submit cascade");
    bus.dispatch_deferred_intents_with_fact_context(&PurgeCascadeHandler::new(), 10)
        .expect("cascade purge");

    assert!(!bus.has_fact(&file.id));
}

#[test]
fn cascade_rejects_child_not_bound_to_deleted_parent() {
    let deletion = deletion_fact([5; 32]);
    let reaction = reaction_fact([6; 32]);
    let intent = cascade_child_purge_intent(CascadeChildPurge {
        workspace_id: WORKSPACE,
        parent_message_id: [5; 32],
        child_kind: CASCADE_CHILD_REACTION,
        child_id: reaction.id,
        parent_deletion_id: deletion.id,
    });
    let mut bus = WakeLoop::new();

    bus.submit_fact(deletion);
    bus.submit_fact(reaction.clone());
    bus.submit_intent(intent).expect("submit cascade");
    let err = bus
        .dispatch_deferred_intents_with_fact_context(&PurgeCascadeHandler::new(), 10)
        .expect_err("unrelated child is rejected");

    assert!(err.contains("parent mismatch"), "{err}");
    assert!(bus.has_fact(&reaction.id));
    assert_eq!(bus.intents().len(), 1);
}

#[test]
fn expiry_purges_due_sealed_message() {
    let message = message_fact(10, 11);
    let intent = expire_message_intent(ExpireMessage {
        workspace_id: WORKSPACE,
        target_id: message.id,
        now_minute: 11,
    });
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.submit_intent(intent).expect("submit expiry");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&RetentionExpiryHandler::new(), 10)
        .expect("expiry purge");

    assert_eq!(report.handled, 1);
    assert!(!bus.has_fact(&message.id));
}

#[test]
fn expiry_rejects_message_that_is_not_due() {
    let message = message_fact(10, 12);
    let intent = expire_message_intent(ExpireMessage {
        workspace_id: WORKSPACE,
        target_id: message.id,
        now_minute: 11,
    });
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.submit_intent(intent).expect("submit expiry");
    let err = bus
        .dispatch_deferred_intents_with_fact_context(&RetentionExpiryHandler::new(), 10)
        .expect_err("early expiry rejected");

    assert!(err.contains("not due"), "{err}");
    assert!(bus.has_fact(&message.id));
    assert_eq!(bus.intents().len(), 1);
}

#[test]
fn floor_purges_sealed_message_below_retire_minute() {
    let setting = setting_fact(30);
    let message = message_fact(29, u64::MAX);
    let intent = apply_retention_floor_intent(ApplyRetentionFloor {
        workspace_id: WORKSPACE,
        setting_id: setting.id,
        target_id: message.id,
    });
    let mut bus = WakeLoop::new();

    bus.submit_fact(setting);
    bus.submit_fact(message.clone());
    bus.submit_intent(intent).expect("submit floor purge");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&RetentionFloorHandler::new(), 10)
        .expect("floor purge");

    assert_eq!(report.handled, 1);
    assert!(!bus.has_fact(&message.id));
}

#[test]
fn floor_rejects_sealed_message_at_or_above_retire_minute() {
    let setting = setting_fact(30);
    let message = message_fact(30, u64::MAX);
    let intent = apply_retention_floor_intent(ApplyRetentionFloor {
        workspace_id: WORKSPACE,
        setting_id: setting.id,
        target_id: message.id,
    });
    let mut bus = WakeLoop::new();

    bus.submit_fact(setting);
    bus.submit_fact(message.clone());
    bus.submit_intent(intent).expect("submit floor purge");
    let err = bus
        .dispatch_deferred_intents_with_fact_context(&RetentionFloorHandler::new(), 10)
        .expect_err("floor mismatch rejected");

    assert!(err.contains("below floor"), "{err}");
    assert!(bus.has_fact(&message.id));
    assert_eq!(bus.intents().len(), 1);
}

fn message_fact(minute: u64, expires_at_minute: u64) -> Fact {
    Fact::new(
        workspace_scope(WORKSPACE),
        minute * 60_000,
        layout::encode_sealed_message(&SealedMessageFact {
            workspace_id: WORKSPACE,
            created_at_ms: minute * 60_000,
            author_user_id: AUTHOR,
            signer_id: [7; 32],
            frontier_id: [8; 32],
            local_history_node_secret_id: [9; 32],
            expires_at_minute,
            disappearing_setting_id: [10; 32],
            minute,
            leaf_id: [11; 32],
            nonce: [12; NONCE_BYTES],
            ciphertext: vec![0x55; CIPHERTEXT_BYTES.min(8)],
        })
        .expect("encode sealed message"),
    )
}

fn deletion_fact(target_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(WORKSPACE),
        1,
        sealed_message::layout::encode_message_deletion(&MessageDeletionFact {
            workspace_id: WORKSPACE,
            target_id,
            author_user_id: AUTHOR,
        })
        .expect("encode deletion"),
    )
}

fn reaction_fact(parent_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(WORKSPACE),
        2,
        content_reaction::layout::encode_fact(&ContentReactionFact {
            workspace_id: WORKSPACE,
            created_at_ms: 2_000,
            target_message_id: parent_id,
            author_user_id: AUTHOR,
            nonce: [13; REACTION_NONCE_BYTES],
            ciphertext: b"sealed-reaction".to_vec(),
        })
        .expect("encode reaction"),
    )
}

fn file_fact(parent_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(WORKSPACE),
        3,
        content_file::layout::encode_fact(&ContentFileFact {
            workspace_id: WORKSPACE,
            created_at_ms: 3_000,
            message_id: parent_id,
            author_user_id: AUTHOR,
            file_id: [14; 32],
            blob_bytes: 128,
            total_slices: 1,
            slice_bytes: 128,
            root_hash: [15; 32],
            sealed_metadata: b"sealed-file".to_vec(),
        })
        .expect("encode file"),
    )
}

fn setting_fact(retire_minute: u64) -> Fact {
    Fact::new(
        workspace_scope(WORKSPACE),
        4,
        disappearing_messages_setting::layout::encode_fact(&DisappearingMessagesSettingFact {
            workspace_id: WORKSPACE,
            supersedes_setting_id: None,
            ttl_minutes: 60,
            retire_minute,
            scope_kind: SCOPE_KIND_WORKSPACE,
            scope_id: WORKSPACE,
            author_user_id: AUTHOR,
            created_at_ms: 4_000,
        })
        .expect("encode setting"),
    )
}

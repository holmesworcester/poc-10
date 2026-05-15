use topo::core::event_bus::EventBus;
use topo::core::facts::Fact;
use topo::core::intents::AtomicIntent;
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::core::projection::{ProjectionContext, Projector};
use topo::event_modules::sealed_message::context::{self, workspace_scope, SecretCoverageMatcher};
use topo::event_modules::sealed_message::fact::{
    MessageDeletionFact, SealedMessageFact, SecretNodeFact, SignerPubkeyFact,
};
use topo::event_modules::sealed_message::rows::{
    decode_message_row, decode_sealed_message_row, MESSAGE_ROWS, SEALED_MESSAGE_ROWS,
};
use topo::event_modules::sealed_message::{layout, project};

#[test]
fn sealed_message_keeps_all_context_needs_until_it_can_open() {
    let workspace = [7; 32];
    let signer = [8; 32];
    let frontier = [9; 32];
    let leaf = [0b1010_1111; 32];
    let message = message_fact(workspace, signer, frontier, 42, leaf);
    let signer_fact = signer_fact(workspace, signer);
    let secret_root = secret_node_fact(workspace, frontier, 0, 99, 0, [0; 32]);
    let mut prefix = [0; 32];
    prefix[0] = 0b1010_1111;
    let secret_internal = secret_node_fact(workspace, frontier, 40, 50, 1, prefix);
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &signer_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = project::SealedMessageProjector::new();
    let mut bus = EventBus::new();

    bus.submit_fact(message.clone());
    let waiting = bus.drain(&projector, &matchers, 10).expect("message waits");
    assert_eq!(waiting.projections, 1);
    assert_eq!(waiting.intents, 0);
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 3);

    bus.submit_fact(signer_fact);
    let signer_seen = bus
        .drain(&projector, &matchers, 10)
        .expect("signer wakes message");
    assert_eq!(signer_seen.wakes, 1);
    assert_eq!(signer_seen.intents, 1);
    let standing = bus.context(&message.id).expect("message still waiting");
    assert_eq!(standing.needs.len(), 2);
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(bus.intents()[0].kind.as_str(), "put_row");
    let sealed_row = match AtomicIntent::from_intent(&bus.intents()[0], &[SEALED_MESSAGE_ROWS])
        .expect("sealed row intent")
    {
        AtomicIntent::PutRow(row) => row,
        AtomicIntent::DeleteRow(_) => panic!("sealed projection should put a row"),
    };
    assert_eq!(
        decode_sealed_message_row(&sealed_row.key, &sealed_row.value)
            .expect("decode sealed row")
            .ciphertext,
        b"sealed".to_vec()
    );

    bus.submit_fact(secret_root);
    bus.submit_fact(secret_internal);
    let opened = bus
        .drain(&projector, &matchers, 10)
        .expect("secret coverage wakes message");

    assert!(opened.wakes >= 1);
    assert_eq!(opened.intents, 1);
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 1);
    assert_eq!(bus.intents().len(), 2);
    assert_eq!(bus.intents()[1].kind.as_str(), "put_row");
    let opened_row = match AtomicIntent::from_intent(&bus.intents()[1], &[MESSAGE_ROWS])
        .expect("message row intent")
    {
        AtomicIntent::PutRow(row) => row,
        AtomicIntent::DeleteRow(_) => panic!("opened projection should put a row"),
    };
    assert_eq!(
        decode_message_row(&opened_row.key, &opened_row.value)
            .expect("decode message row")
            .leaf_id,
        leaf
    );

    let deletion = deletion_fact(workspace, message.id);
    bus.submit_fact(deletion);
    let purged = bus
        .drain(&projector, &matchers, 10)
        .expect("deletion wakes opened message");
    assert_eq!(purged.wakes, 1);
    assert_eq!(purged.intents, 3);
    assert!(bus.context(&message.id).is_none());
    assert_eq!(bus.intents().len(), 5);
    assert_eq!(bus.intents()[2].kind.as_str(), "delete_row");
    assert_eq!(bus.intents()[3].kind.as_str(), "delete_row");
    assert_eq!(bus.intents()[4].kind.as_str(), "purge_event");

    let secret_leaf = secret_node_fact(workspace, frontier, 42, 42, 32, leaf);
    bus.submit_fact(secret_leaf);
    let duplicate = bus
        .drain(&projector, &matchers, 10)
        .expect("extra secret offer does not reopen");
    assert_eq!(duplicate.intents, 0);
    assert_eq!(bus.intents().len(), 5);
}

#[test]
fn deletion_update_purges_message_before_keys_arrive() {
    let workspace = [17; 32];
    let signer = [18; 32];
    let frontier = [19; 32];
    let leaf = [20; 32];
    let message = message_fact(workspace, signer, frontier, 42, leaf);
    let deletion = deletion_fact(workspace, message.id);
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &signer_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = project::SealedMessageProjector::new();
    let mut bus = EventBus::new();

    bus.submit_fact(message.clone());
    bus.drain(&projector, &matchers, 10).expect("message waits");
    bus.submit_fact(deletion);
    let purged = bus
        .drain(&projector, &matchers, 10)
        .expect("deletion purges without keys");

    assert_eq!(purged.wakes, 1);
    assert_eq!(purged.intents, 3);
    assert!(bus.context(&message.id).is_none());
    assert_eq!(bus.intents()[0].kind.as_str(), "delete_row");
    assert_eq!(bus.intents()[1].kind.as_str(), "delete_row");
    assert_eq!(bus.intents()[2].kind.as_str(), "purge_event");

    bus.submit_fact(signer_fact(workspace, signer));
    bus.submit_fact(secret_node_fact(workspace, frontier, 0, 99, 0, [0; 32]));
    let later_context = bus
        .drain(&projector, &matchers, 10)
        .expect("later keys do not reopen purged message");
    assert_eq!(later_context.intents, 0);
    assert_eq!(bus.intents().len(), 3);
}

#[test]
fn sealed_message_projector_rejects_body_scope_mismatches() {
    let workspace = [31; 32];
    let other_workspace = [32; 32];
    let signer = [33; 32];
    let frontier = [34; 32];
    let message = message_fact(workspace, signer, frontier, 42, [35; 32]);
    let projector = project::SealedMessageProjector::new();
    let context = ProjectionContext::new(Vec::new());

    let bad_message = Fact::new(
        workspace_scope(other_workspace),
        message.timestamp,
        message.bytes.clone(),
    );
    let err = projector
        .project(&bad_message, &context)
        .expect_err("message scope mismatch rejects");
    assert!(err.contains("scope does not match body workspace"), "{err}");

    let secret = secret_node_fact(workspace, frontier, 0, 99, 0, [0; 32]);
    let bad_secret = Fact::new(
        workspace_scope(other_workspace),
        secret.timestamp,
        secret.bytes.clone(),
    );
    let err = projector
        .project(&bad_secret, &context)
        .expect_err("secret scope mismatch rejects");
    assert!(err.contains("scope does not match body workspace"), "{err}");

    let deletion = deletion_fact(workspace, message.id);
    let bad_deletion = Fact::new(
        workspace_scope(other_workspace),
        deletion.timestamp,
        deletion.bytes.clone(),
    );
    let err = projector
        .project(&bad_deletion, &context)
        .expect_err("deletion scope mismatch rejects");
    assert!(err.contains("scope does not match body workspace"), "{err}");
}

fn message_fact(
    workspace_id: [u8; 32],
    signer_id: [u8; 32],
    frontier_id: [u8; 32],
    minute: u64,
    leaf_id: [u8; 32],
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        minute,
        layout::encode_sealed_message(&SealedMessageFact {
            workspace_id,
            signer_id,
            frontier_id,
            minute,
            leaf_id,
            ciphertext: b"sealed".to_vec(),
        })
        .expect("encode sealed message"),
    )
}

fn signer_fact(workspace_id: [u8; 32], signer_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        1,
        layout::encode_signer_pubkey(&SignerPubkeyFact {
            signer_id,
            public_key: [5; 32],
        })
        .expect("encode signer"),
    )
}

fn deletion_fact(workspace_id: [u8; 32], target_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        2,
        layout::encode_message_deletion(&MessageDeletionFact {
            workspace_id,
            target_id,
        })
        .expect("encode deletion"),
    )
}

fn secret_node_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    start_minute: u64,
    end_minute: u64,
    prefix_bytes: u8,
    leaf_prefix: [u8; 32],
) -> Fact {
    let bytes = layout::encode_secret_node(&SecretNodeFact {
        workspace_id,
        frontier_id,
        start_minute,
        end_minute,
        prefix_bytes,
        leaf_prefix,
    })
    .expect("encode secret node");
    Fact::new(workspace_scope(workspace_id), start_minute, bytes)
}

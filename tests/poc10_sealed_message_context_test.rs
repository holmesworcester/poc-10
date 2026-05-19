use topo::core::crypto;
use topo::core::facts::Fact;
use topo::core::intents::AtomicIntent;
use topo::core::matchers::ContextMatcher;
use topo::core::projection::{ProjectionContext, Projector};
use topo::core::wake_loop::WakeLoop;
use topo::protocol::facts::content::sealed_message::fact::{
    MessageDeletionFact, SealedMessageFact, SecretNodeFact, SignerPubkeyFact, NONCE_BYTES,
};
use topo::protocol::facts::content::sealed_message::rows::{
    decode_message_tombstone_row, decode_sealed_message_row, message_key, MESSAGE_ROWS,
    MESSAGE_TOMBSTONE_ROWS, OPENED_MESSAGE_ROWS, SEALED_MESSAGE_ROWS,
};
use topo::protocol::facts::content::sealed_message::{create as sealed_create, layout, project};
use topo::protocol::facts::encryption::fact::{LocalKeySecretFact, RemovalFrontierFact};
use topo::protocol::facts::encryption::layout as encryption_layout;
use topo::protocol::intents::sync::share_fact_with_workspace;
use topo::protocol::matchers::ExactSelectorMatcher;
use topo::protocol::matchers::{self as context, workspace_scope, SecretCoverageMatcher};
use topo::protocol::runtime::ProtocolProjector;

const DEFAULT_AUTHOR: [u8; 32] = [6; 32];
const DEFAULT_SECRET: [u8; 32] = [0x66; 32];

#[test]
fn sealed_message_keeps_context_until_secret_coverage_and_deletion() {
    let workspace = [7; 32];
    let signer = [8; 32];
    let frontier = removal_frontier_fact(workspace, [0x71; 32], 9);
    let frontier_id = frontier.id;
    let leaf = [0b1010_1111; 32];
    let message = message_fact(workspace, signer, frontier_id, 42, leaf);
    let message_signer_fact = signer_fact(workspace, signer);
    let frontier_owner_fact = signer_fact(workspace, [0x71; 32]);
    let secret_root = local_key_secret_fact(workspace, frontier_id, [0x71; 32]);
    let mut prefix = [0; 32];
    prefix[0] = 0b1010_1111;
    let secret_internal = secret_node_fact(workspace, frontier_id, 40, 50, 1, prefix);
    let frontier_matcher = ExactSelectorMatcher::new(topo::protocol::matchers::frontier_role());
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &frontier_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    let waiting = bus.drain(&projector, &matchers, 10).expect("message waits");
    assert_eq!(waiting.projections, 1);
    assert_eq!(waiting.intents, 0);
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 3);

    bus.submit_fact(message_signer_fact);
    let signer_seen = bus
        .drain(&projector, &matchers, 10)
        .expect("signer wakes message");
    assert_eq!(signer_seen.wakes, 1);
    assert_eq!(signer_seen.intents, 2);
    let standing = bus.context(&message.id).expect("message still waiting");
    assert_eq!(standing.needs.len(), 3);
    assert_eq!(count_kind(bus.intents(), "share_fact_with_workspace"), 1);
    assert_share_intent(bus.intents(), workspace, message.id);
    let sealed_row = first_put_row(bus.intents(), SEALED_MESSAGE_ROWS);
    assert_eq!(sealed_row.key, message_key(workspace, message.id));
    assert_eq!(
        decode_sealed_message_row(&sealed_row.key, &sealed_row.value)
            .expect("decode sealed row")
            .ciphertext,
        message_body(&message).ciphertext
    );

    bus.submit_fact(frontier_owner_fact);
    bus.submit_fact(frontier);
    bus.submit_fact(secret_root);
    bus.submit_fact(secret_internal);
    let covered = bus
        .drain(&projector, &matchers, 10)
        .expect("secret coverage wakes message");

    assert!(covered.wakes >= 1);
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 2);
    first_put_row(bus.intents(), MESSAGE_ROWS);
    first_put_row(bus.intents(), OPENED_MESSAGE_ROWS);

    let deletion = deletion_fact(workspace, message.id);
    bus.submit_fact(deletion);
    let purged = bus
        .drain(&projector, &matchers, 10)
        .expect("deletion wakes covered message");
    assert_eq!(purged.wakes, 1);
    assert!(bus.context(&message.id).is_none());
    assert_eq!(count_kind(bus.intents(), "delete_row"), 3);
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 1);
    let tombstone = first_put_row(bus.intents(), MESSAGE_TOMBSTONE_ROWS);
    assert_eq!(
        decode_message_tombstone_row(&tombstone.key, &tombstone.value)
            .expect("decode tombstone")
            .authored_minute,
        42
    );
    let intent_count = bus.intents().len();

    let secret_leaf = secret_node_fact(workspace, frontier_id, 42, 42, 32, leaf);
    bus.submit_fact(secret_leaf);
    let duplicate = bus
        .drain(&projector, &matchers, 10)
        .expect("extra secret offer does not reopen");
    assert_eq!(duplicate.intents, 0);
    assert_eq!(bus.intents().len(), intent_count);
}

#[test]
fn deletion_update_purges_message_before_keys_arrive() {
    let workspace = [17; 32];
    let signer = [18; 32];
    let frontier = removal_frontier_fact(workspace, [0x72; 32], 19);
    let frontier_id = frontier.id;
    let leaf = [20; 32];
    let message = message_fact(workspace, signer, frontier_id, 42, leaf);
    let deletion = deletion_fact(workspace, message.id);
    let deletion_id = deletion.id;
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &signer_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.drain(&projector, &matchers, 10).expect("message waits");
    bus.submit_fact(deletion);
    let purged = bus
        .drain(&projector, &matchers, 10)
        .expect("deletion purges without keys");

    assert_eq!(purged.wakes, 1);
    assert!(bus.context(&message.id).is_none());
    assert_share_intent(bus.intents(), workspace, deletion_id);
    assert_eq!(
        non_share_kinds(bus.intents()),
        vec![
            "put_row",
            "delete_row",
            "delete_row",
            "delete_row",
            "purge_deleted_message"
        ]
    );

    bus.submit_fact(signer_fact(workspace, signer));
    bus.submit_fact(signer_fact(workspace, [0x73; 32]));
    bus.submit_fact(frontier);
    bus.submit_fact(local_key_secret_fact(workspace, frontier_id, [0x72; 32]));
    let later_context = bus
        .drain(&projector, &matchers, 10)
        .expect("later keys do not reopen purged message");
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 1);
    assert_eq!(count_kind(bus.intents(), "delete_row"), 3);
    assert_eq!(count_kind(bus.intents(), "put_row"), 1);
    assert!(later_context.intents <= 1);
}

#[test]
fn non_author_deletion_does_not_purge_or_wake_message() {
    let workspace = [21; 32];
    let signer = [22; 32];
    let frontier = removal_frontier_fact(workspace, [0x73; 32], 23);
    let frontier_id = frontier.id;
    let leaf = [24; 32];
    let message = message_fact(workspace, signer, frontier_id, 42, leaf);
    let wrong_deletion = deletion_fact_by_author(workspace, message.id, [25; 32]);
    let wrong_deletion_id = wrong_deletion.id;
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let frontier_matcher = ExactSelectorMatcher::new(topo::protocol::matchers::frontier_role());
    let matchers = [
        &frontier_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    bus.drain(&projector, &matchers, 10).expect("message waits");
    bus.submit_fact(wrong_deletion);
    let ignored = bus
        .drain(&projector, &matchers, 10)
        .expect("non-author deletion projects as unrelated offer");

    assert_eq!(ignored.wakes, 0);
    assert_eq!(ignored.intents, 1);
    assert_share_intent(bus.intents(), workspace, wrong_deletion_id);
    assert!(non_share_kinds(bus.intents()).is_empty());
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 3);

    bus.submit_fact(signer_fact(workspace, signer));
    bus.submit_fact(signer_fact(workspace, [0x73; 32]));
    bus.submit_fact(frontier);
    bus.submit_fact(local_key_secret_fact(workspace, frontier_id, [0x73; 32]));
    bus.drain(&projector, &matchers, 30)
        .expect("valid context still projects sealed row");

    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 2);
    first_put_row(bus.intents(), SEALED_MESSAGE_ROWS);
    first_put_row(bus.intents(), MESSAGE_ROWS);
    first_put_row(bus.intents(), OPENED_MESSAGE_ROWS);
}

#[test]
fn deletion_before_message_purges_when_target_later_arrives() {
    let workspace = [26; 32];
    let signer = [27; 32];
    let frontier = removal_frontier_fact(workspace, [0x74; 32], 28);
    let message = message_fact(workspace, signer, frontier.id, 42, [29; 32]);
    let deletion = deletion_fact(workspace, message.id);
    let deletion_id = deletion.id;
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &signer_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

    bus.submit_fact(deletion);
    bus.drain(&projector, &matchers, 10)
        .expect("deletion offer stands");
    assert_share_intent(bus.intents(), workspace, deletion_id);
    bus.submit_fact(message.clone());
    let purged = bus
        .drain(&projector, &matchers, 10)
        .expect("message sees prior deletion");

    assert!(purged.wakes >= 1);
    assert_eq!(purged.intents, 5);
    assert!(bus.context(&message.id).is_none());
    assert_eq!(
        non_share_kinds(bus.intents()),
        vec![
            "put_row",
            "delete_row",
            "delete_row",
            "delete_row",
            "purge_deleted_message"
        ]
    );
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

#[test]
fn sealed_message_projector_revalidates_secret_context_before_clearing_need() {
    let workspace = [41; 32];
    let signer = [42; 32];
    let frontier = [43; 32];
    let message = message_fact(workspace, signer, frontier, 42, [44; 32]);
    let signer_offer = context::signer_offer([45; 32], workspace_scope(workspace), signer);
    let wrong_secret_offer = context::secret_offer(
        [46; 32],
        workspace_scope(workspace),
        workspace,
        [47; 32],
        0,
        99,
        0,
        [0; 32],
    );
    let projector = project::SealedMessageProjector::new();

    let output = projector
        .project(
            &message,
            &ProjectionContext::new(vec![signer_offer, wrong_secret_offer]),
        )
        .expect("project with mismatched context");

    assert!(
        output
            .needs
            .iter()
            .any(|need| need.role == context::secret_role()),
        "wrong secret coverage must leave the secret need standing"
    );
    assert!(
        output
            .intents
            .iter()
            .all(|intent| AtomicIntent::from_intent(intent, &[MESSAGE_ROWS]).is_err()),
        "wrong secret coverage must not materialize a plaintext row"
    );
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
            created_at_ms: minute * 60_000,
            author_user_id: DEFAULT_AUTHOR,
            signer_id,
            frontier_id,
            local_history_node_secret_id: [10; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [11; 32],
            minute,
            leaf_id,
            nonce: [12; NONCE_BYTES],
            ciphertext: encrypted_body(workspace_id, frontier_id, minute, DEFAULT_SECRET),
        })
        .expect("encode sealed message"),
    )
}

fn message_body(message: &Fact) -> SealedMessageFact {
    layout::decode_sealed_message(&message.bytes).expect("decode message")
}

fn encrypted_body(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    minute: u64,
    secret_key: [u8; 32],
) -> Vec<u8> {
    let plaintext = sealed_create::pad_plaintext(b"sealed").expect("pad plaintext");
    crypto::xchacha20poly1305_encrypt(
        &secret_key,
        &sealed_create::associated_data(workspace_id, frontier_id, minute),
        &[12; NONCE_BYTES],
        &plaintext,
    )
    .expect("encrypt sealed test message")
}

fn removal_frontier_fact(
    workspace_id: [u8; 32],
    owner_endpoint_id: [u8; 32],
    created_at_ms: u64,
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        created_at_ms,
        encryption_layout::encode_removal_frontier(&RemovalFrontierFact {
            workspace_id,
            owner_endpoint_id,
            created_at_ms,
        })
        .expect("encode frontier"),
    )
}

fn local_key_secret_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    owner_endpoint_id: [u8; 32],
) -> Fact {
    Fact::new(
        topo::core::facts::FactScope::Local,
        3,
        encryption_layout::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            created_at_ms: 3,
            key_secret: DEFAULT_SECRET,
        })
        .expect("encode local secret"),
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
    deletion_fact_by_author(workspace_id, target_id, DEFAULT_AUTHOR)
}

fn deletion_fact_by_author(
    workspace_id: [u8; 32],
    target_id: [u8; 32],
    author_user_id: [u8; 32],
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        2,
        layout::encode_message_deletion(&MessageDeletionFact {
            workspace_id,
            created_at_ms: 2,
            target_id,
            author_user_id,
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

fn count_kind(intents: &[topo::core::intents::Intent], kind: &str) -> usize {
    intents
        .iter()
        .filter(|intent| intent.kind.as_str() == kind)
        .count()
}

fn non_share_kinds(intents: &[topo::core::intents::Intent]) -> Vec<&str> {
    intents
        .iter()
        .map(|intent| intent.kind.as_str())
        .filter(|kind| *kind != "share_fact_with_workspace")
        .collect()
}

fn first_put_row(
    intents: &[topo::core::intents::Intent],
    table: topo::core::store::TableName,
) -> topo::core::store::TableRow {
    for intent in intents {
        if let Ok(AtomicIntent::PutRow(row)) = AtomicIntent::from_intent(intent, &[table]) {
            return row;
        }
    }
    panic!("missing put_row for {}", table.as_str());
}

fn assert_share_intent(
    intents: &[topo::core::intents::Intent],
    workspace_id: [u8; 32],
    fact_id: [u8; 32],
) {
    let found = intents.iter().any(|intent| {
        if intent.kind.as_str() != "share_fact_with_workspace" {
            return false;
        }
        let Ok(input) = share_fact_with_workspace::decode_share_fact_with_workspace(intent) else {
            return false;
        };
        input.workspace_id == workspace_id && input.fact_id == fact_id
    });
    assert!(found, "missing share_fact_with_workspace intent");
}

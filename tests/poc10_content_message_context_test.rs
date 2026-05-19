use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::matchers::ContextMatcher;
use topo::core::wake_loop::WakeLoop;
use topo::protocol::facts::content::message::fact::{ContentMessageFact, NONCE_BYTES};
use topo::protocol::facts::content::message::rows::{
    decode_content_message_row, decode_message_tombstone_row, CONTENT_MESSAGE_ROWS,
    MESSAGE_TOMBSTONE_ROWS, OPENED_MESSAGE_ROWS,
};
use topo::protocol::facts::content::message::{create as message_create, layout as message_layout};
use topo::protocol::facts::content::message_deletion::fact::ContentMessageDeletionFact;
use topo::protocol::facts::content::message_deletion::layout as message_deletion_layout;
use topo::protocol::facts::encryption::fact::{LocalKeySecretFact, RemovalFrontierFact};
use topo::protocol::facts::encryption::layout as encryption_layout;
use topo::protocol::facts::identity;
use topo::protocol::facts::identity::device_invite::fact::DeviceInviteFact;
use topo::protocol::facts::identity::device_invite::layout as device_invite_layout;
use topo::protocol::facts::identity::endpoint_shared::fact::{EndpointRole, EndpointSharedFact};
use topo::protocol::facts::identity::endpoint_shared::layout as endpoint_shared_layout;
use topo::protocol::facts::identity::user::fact::UserFact;
use topo::protocol::facts::identity::user::layout as user_layout;
use topo::protocol::facts::identity::user_invite::fact::UserInviteFact;
use topo::protocol::facts::identity::user_invite::layout as user_invite_layout;
use topo::protocol::facts::identity::workspace::fact::WorkspaceFact;
use topo::protocol::facts::identity::workspace::layout as workspace_layout;
use topo::protocol::intents::sync::share_fact_with_workspace;
use topo::protocol::matchers::ExactSelectorMatcher;
use topo::protocol::matchers::{self as context, workspace_scope, SecretCoverageMatcher};
use topo::protocol::runtime::ProtocolProjector;

const WORKSPACE_PRIVATE_KEY: [u8; 32] = [0x41; 32];
const DEFAULT_AUTHOR_PRIVATE_KEY: [u8; 32] = [0x42; 32];
const DEVICE_INVITE_PRIVATE_KEY: [u8; 32] = [0x43; 32];
const DEFAULT_SECRET: [u8; 32] = [0x66; 32];

#[test]
fn content_message_keeps_context_until_secret_coverage_and_deletion() {
    let workspace = [7; 32];
    let signer = [8; 32];
    let frontier = removal_frontier_fact(workspace, [0x71; 32], 9);
    let frontier_id = frontier.id;
    let leaf = [0b1010_1111; 32];
    let workspace_matcher = ExactSelectorMatcher::new(context::workspace_role());
    let user_invite_matcher = ExactSelectorMatcher::new(context::user_invite_role());
    let user_matcher = ExactSelectorMatcher::new(context::user_role());
    let device_invite_matcher = ExactSelectorMatcher::new(context::device_invite_role());
    let frontier_matcher = ExactSelectorMatcher::new(topo::protocol::matchers::frontier_role());
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let message_meta_matcher = ExactSelectorMatcher::new(context::message_meta_role());
    let message_matcher = ExactSelectorMatcher::new(context::message_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &workspace_matcher as &dyn ContextMatcher,
        &user_invite_matcher as &dyn ContextMatcher,
        &user_matcher as &dyn ContextMatcher,
        &device_invite_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
        &message_meta_matcher as &dyn ContextMatcher,
        &message_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();
    let author = seed_author_context(&mut bus, &projector, &matchers, workspace);
    let message = message_fact(workspace, signer, frontier_id, 42, leaf, author.id);
    let secret_root = local_key_secret_fact(workspace, frontier_id, [0x71; 32]);

    bus.submit_fact(message.clone());
    let waiting = bus.drain(&projector, &matchers, 10).expect("message waits");
    assert!(waiting.projections >= 1);
    assert_eq!(count_kind(bus.intents(), "share_fact_with_workspace"), 1);
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 4);
    assert_share_intent(bus.intents(), workspace, message.id);
    assert!(find_put_row(bus.intents(), CONTENT_MESSAGE_ROWS).is_none());
    assert!(find_put_row(bus.intents(), OPENED_MESSAGE_ROWS).is_none());
    bus.take_intents();

    submit_signer_context(&mut bus, workspace, author.id, signer);
    let signer_seen = bus
        .drain(&projector, &matchers, 10)
        .expect("signer wakes message");
    assert!(signer_seen.wakes >= 1);
    assert!(signer_seen.intents >= 1);
    let standing = bus.context(&message.id).expect("message still waiting");
    assert_eq!(standing.needs.len(), 4);
    assert_share_intent(bus.intents(), workspace, message.id);
    assert!(find_put_row(bus.intents(), CONTENT_MESSAGE_ROWS).is_none());
    assert!(find_put_row(bus.intents(), OPENED_MESSAGE_ROWS).is_none());
    bus.take_intents();

    submit_signer_context(&mut bus, workspace, author.id, [0x71; 32]);
    bus.submit_fact(frontier);
    bus.submit_fact(secret_root);
    let covered = bus
        .drain(&projector, &matchers, 10)
        .expect("secret coverage wakes message");

    assert!(covered.wakes >= 1);
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 4);
    let content_row = first_put_row(bus.intents(), CONTENT_MESSAGE_ROWS);
    assert_eq!(
        decode_content_message_row(&content_row.key, &content_row.value)
            .expect("decode content message row")
            .message_id,
        message.id
    );
    first_put_row(bus.intents(), OPENED_MESSAGE_ROWS);
    bus.take_intents();

    let deletion = deletion_fact(workspace, message.id);
    bus.submit_fact(deletion);
    let purged = bus
        .drain(&projector, &matchers, 10)
        .expect("deletion wakes covered message");
    assert!(purged.wakes >= 1);
    assert!(bus.context(&message.id).is_none());
    assert_eq!(count_kind(bus.intents(), "delete_row"), 2);
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 1);
    let tombstone = first_put_row(bus.intents(), MESSAGE_TOMBSTONE_ROWS);
    assert_eq!(
        decode_message_tombstone_row(&tombstone.key, &tombstone.value)
            .expect("decode tombstone")
            .authored_minute,
        42
    );
    let intent_count = bus.intents().len();
    let duplicate = bus
        .drain(&projector, &matchers, 10)
        .expect("idle drain does not reopen purged message");
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
    let workspace_matcher = ExactSelectorMatcher::new(context::workspace_role());
    let user_invite_matcher = ExactSelectorMatcher::new(context::user_invite_role());
    let user_matcher = ExactSelectorMatcher::new(context::user_role());
    let device_invite_matcher = ExactSelectorMatcher::new(context::device_invite_role());
    let frontier_matcher = ExactSelectorMatcher::new(topo::protocol::matchers::frontier_role());
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let message_meta_matcher = ExactSelectorMatcher::new(context::message_meta_role());
    let message_matcher = ExactSelectorMatcher::new(context::message_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &workspace_matcher as &dyn ContextMatcher,
        &user_invite_matcher as &dyn ContextMatcher,
        &user_matcher as &dyn ContextMatcher,
        &device_invite_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
        &message_meta_matcher as &dyn ContextMatcher,
        &message_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();
    let author = seed_author_context(&mut bus, &projector, &matchers, workspace);
    let message = message_fact(workspace, signer, frontier_id, 42, leaf, author.id);
    let deletion = deletion_fact(workspace, message.id);

    bus.submit_fact(message.clone());
    bus.drain(&projector, &matchers, 10).expect("message waits");
    bus.take_intents();
    bus.submit_fact(deletion);
    let waiting_delete = bus
        .drain(&projector, &matchers, 10)
        .expect("deletion waits for authenticated message metadata");

    assert!(waiting_delete.wakes <= 1);
    assert!(bus.context(&message.id).is_some());
    assert_eq!(count_kind(bus.intents(), "delete_row"), 0);
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 0);
    assert!(non_share_kinds(bus.intents()).is_empty());
    bus.take_intents();

    submit_signer_context(&mut bus, workspace, author.id, signer);
    let later_context = bus
        .drain(&projector, &matchers, 100)
        .expect("authenticated metadata lets deletion purge before keys arrive");
    assert!(later_context.wakes >= 2);
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 1);
    assert_eq!(count_kind(bus.intents(), "delete_row"), 2);
    assert!(bus.context(&message.id).is_none());

    bus.take_intents();
    submit_signer_context(&mut bus, workspace, author.id, [0x72; 32]);
    bus.submit_fact(frontier);
    bus.submit_fact(local_key_secret_fact(workspace, frontier_id, [0x72; 32]));
    let later_key = bus
        .drain(&projector, &matchers, 100)
        .expect("later keys do not reopen a purged message");
    assert!(later_key.intents <= 3);
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 0);
    assert!(find_put_row(bus.intents(), CONTENT_MESSAGE_ROWS).is_none());
    assert!(find_put_row(bus.intents(), OPENED_MESSAGE_ROWS).is_none());
}

#[test]
fn non_author_deletion_does_not_purge_or_wake_message() {
    let workspace = [21; 32];
    let signer = [22; 32];
    let frontier = removal_frontier_fact(workspace, [0x73; 32], 23);
    let frontier_id = frontier.id;
    let leaf = [24; 32];
    let workspace_matcher = ExactSelectorMatcher::new(context::workspace_role());
    let user_invite_matcher = ExactSelectorMatcher::new(context::user_invite_role());
    let user_matcher = ExactSelectorMatcher::new(context::user_role());
    let device_invite_matcher = ExactSelectorMatcher::new(context::device_invite_role());
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let message_meta_matcher = ExactSelectorMatcher::new(context::message_meta_role());
    let message_matcher = ExactSelectorMatcher::new(context::message_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let frontier_matcher = ExactSelectorMatcher::new(topo::protocol::matchers::frontier_role());
    let matchers = [
        &workspace_matcher as &dyn ContextMatcher,
        &user_invite_matcher as &dyn ContextMatcher,
        &user_matcher as &dyn ContextMatcher,
        &device_invite_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
        &message_meta_matcher as &dyn ContextMatcher,
        &message_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();
    let author = seed_author_context(&mut bus, &projector, &matchers, workspace);
    let message = message_fact(workspace, signer, frontier_id, 42, leaf, author.id);
    let wrong_deletion = deletion_fact_by_author(workspace, message.id, [25; 32]);

    bus.submit_fact(message.clone());
    bus.drain(&projector, &matchers, 10).expect("message waits");
    bus.take_intents();
    bus.submit_fact(wrong_deletion);
    let ignored = bus
        .drain(&projector, &matchers, 10)
        .expect("non-author deletion waits without message context");

    assert_eq!(ignored.wakes, 0);
    assert_eq!(ignored.intents, 0);
    assert!(non_share_kinds(bus.intents()).is_empty());
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 4);

    submit_signer_context(&mut bus, workspace, author.id, signer);
    submit_signer_context(&mut bus, workspace, author.id, [0x73; 32]);
    bus.submit_fact(frontier);
    bus.submit_fact(local_key_secret_fact(workspace, frontier_id, [0x73; 32]));
    bus.drain(&projector, &matchers, 30)
        .expect("valid context still opens the message without a deletion");

    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 4);
    first_put_row(bus.intents(), CONTENT_MESSAGE_ROWS);
    first_put_row(bus.intents(), OPENED_MESSAGE_ROWS);
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 0);
}

#[test]
fn deletion_before_message_purges_when_target_later_arrives() {
    let workspace = [26; 32];
    let signer = [27; 32];
    let frontier = removal_frontier_fact(workspace, [0x74; 32], 28);
    let frontier_id = frontier.id;
    let workspace_matcher = ExactSelectorMatcher::new(context::workspace_role());
    let user_invite_matcher = ExactSelectorMatcher::new(context::user_invite_role());
    let user_matcher = ExactSelectorMatcher::new(context::user_role());
    let device_invite_matcher = ExactSelectorMatcher::new(context::device_invite_role());
    let frontier_matcher = ExactSelectorMatcher::new(topo::protocol::matchers::frontier_role());
    let signer_matcher = ExactSelectorMatcher::new(context::signer_role());
    let message_meta_matcher = ExactSelectorMatcher::new(context::message_meta_role());
    let message_matcher = ExactSelectorMatcher::new(context::message_role());
    let deletion_matcher = ExactSelectorMatcher::new(context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &workspace_matcher as &dyn ContextMatcher,
        &user_invite_matcher as &dyn ContextMatcher,
        &user_matcher as &dyn ContextMatcher,
        &device_invite_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
        &message_meta_matcher as &dyn ContextMatcher,
        &message_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();
    let author = seed_author_context(&mut bus, &projector, &matchers, workspace);
    let message = message_fact(workspace, signer, frontier_id, 42, [29; 32], author.id);
    let deletion = deletion_fact(workspace, message.id);

    bus.submit_fact(deletion);
    bus.drain(&projector, &matchers, 10)
        .expect("deletion waits for target message metadata");
    assert!(bus.intents().is_empty());
    bus.submit_fact(message.clone());
    let waiting_message = bus
        .drain(&projector, &matchers, 10)
        .expect("message waits for authenticated context before deletion can match");

    assert!(waiting_message.wakes <= 1);
    assert!(bus.context(&message.id).is_some());
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 0);
    bus.take_intents();

    submit_signer_context(&mut bus, workspace, author.id, signer);
    let purged = bus
        .drain(&projector, &matchers, 100)
        .expect("authenticated target metadata lets prior deletion purge message");

    assert!(purged.wakes >= 2);
    assert!(bus.context(&message.id).is_none());
    assert_eq!(count_kind(bus.intents(), "delete_row"), 2);
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 1);

    bus.take_intents();
    submit_signer_context(&mut bus, workspace, author.id, [0x74; 32]);
    bus.submit_fact(frontier);
    bus.submit_fact(local_key_secret_fact(workspace, frontier_id, [0x74; 32]));
    let later_key = bus
        .drain(&projector, &matchers, 100)
        .expect("later keys do not reopen a purged message");
    assert!(later_key.intents <= 3);
    assert_eq!(count_kind(bus.intents(), "purge_deleted_message"), 0);
    assert!(find_put_row(bus.intents(), CONTENT_MESSAGE_ROWS).is_none());
    assert!(find_put_row(bus.intents(), OPENED_MESSAGE_ROWS).is_none());
}

fn message_fact(
    workspace_id: [u8; 32],
    signer_id: [u8; 32],
    frontier_id: [u8; 32],
    minute: u64,
    leaf_id: [u8; 32],
    author_user_id: [u8; 32],
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        minute,
        message_layout::encode_fact(&ContentMessageFact {
            workspace_id,
            created_at_ms: minute * 60_000,
            author_user_id,
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
        .expect("encode content message"),
    )
}

fn encrypted_body(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    minute: u64,
    secret_key: [u8; 32],
) -> Vec<u8> {
    let plaintext = message_create::pad_plaintext(b"hidden").expect("pad plaintext");
    crypto::xchacha20poly1305_encrypt(
        &secret_key,
        &message_create::associated_data(workspace_id, frontier_id, minute),
        &[12; NONCE_BYTES],
        &plaintext,
    )
    .expect("encrypt content message test body")
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

fn seed_author_context(
    bus: &mut WakeLoop,
    projector: &ProtocolProjector,
    matchers: &[&dyn ContextMatcher],
    workspace_id: [u8; 32],
) -> Fact {
    let workspace = workspace_fact(workspace_id);
    let invite = signed_user_invite_fact(workspace_id);
    let author = default_author_fact(workspace_id);
    bus.submit_fact(workspace);
    bus.submit_fact(invite);
    bus.submit_fact(author.clone());
    bus.drain(projector, matchers, 30)
        .expect("seed author identity context");
    bus.take_intents();
    author
}

fn workspace_fact(workspace_id: [u8; 32]) -> Fact {
    Fact {
        id: workspace_id,
        scope: FactScope::Global,
        timestamp: 1,
        bytes: workspace_layout::encode_fact(&WorkspaceFact {
            created_at_ms: 1,
            public_key: crypto::ed25519_public_key(&WORKSPACE_PRIVATE_KEY),
            name: "Workspace".to_string(),
        })
        .expect("encode workspace"),
    }
}

fn signed_user_invite_fact(workspace_id: [u8; 32]) -> Fact {
    let invite = UserInviteFact {
        created_at_ms: 2,
        public_key: crypto::ed25519_public_key(&DEFAULT_AUTHOR_PRIVATE_KEY),
        workspace_id,
        authority_fact_id: workspace_id,
    };
    make_signed_fact(
        workspace_id,
        WORKSPACE_PRIVATE_KEY,
        user_invite_layout::encode_fact(&invite).expect("encode user invite"),
        invite.created_at_ms,
    )
}

fn default_author_fact(workspace_id: [u8; 32]) -> Fact {
    let invite = signed_user_invite_fact(workspace_id);
    let user = UserFact {
        created_at_ms: 3,
        workspace_id,
        public_key: crypto::ed25519_public_key(&DEFAULT_AUTHOR_PRIVATE_KEY),
        username: "author".to_string(),
    };
    make_signed_fact(
        invite.id,
        DEFAULT_AUTHOR_PRIVATE_KEY,
        user_layout::encode_fact(&user).expect("encode user"),
        user.created_at_ms,
    )
}

fn submit_signer_context(
    bus: &mut WakeLoop,
    workspace_id: [u8; 32],
    author_user_id: [u8; 32],
    signer_id: [u8; 32],
) {
    let user_invite_id = signed_user_invite_fact(workspace_id).id;
    let device_invite = signed_device_invite_fact(workspace_id, author_user_id, user_invite_id);
    let endpoint =
        signed_endpoint_shared_fact(workspace_id, author_user_id, signer_id, device_invite.id);
    bus.submit_fact(device_invite);
    bus.submit_fact(endpoint);
}

fn signed_device_invite_fact(
    workspace_id: [u8; 32],
    author_user_id: [u8; 32],
    user_invite_id: [u8; 32],
) -> Fact {
    let invite = DeviceInviteFact {
        created_at_ms: 4,
        workspace_id,
        user_authority_fact_id: author_user_id,
        user_invite_fact_id: Some(user_invite_id),
        public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
    };
    make_signed_fact(
        author_user_id,
        DEFAULT_AUTHOR_PRIVATE_KEY,
        device_invite_layout::encode_fact(&invite).expect("encode device invite"),
        invite.created_at_ms,
    )
}

fn signed_endpoint_shared_fact(
    workspace_id: [u8; 32],
    author_user_id: [u8; 32],
    endpoint_id: [u8; 32],
    device_invite_id: [u8; 32],
) -> Fact {
    let endpoint = EndpointSharedFact {
        created_at_ms: 5,
        workspace_id,
        user_authority_fact_id: author_user_id,
        endpoint_id,
        signing_public_key: crypto::ed25519_public_key(&DEVICE_INVITE_PRIVATE_KEY),
        endpoint_role: EndpointRole::Device,
        device_name: "device".to_string(),
    };
    make_signed_fact(
        device_invite_id,
        DEVICE_INVITE_PRIVATE_KEY,
        endpoint_shared_layout::encode_fact(&endpoint).expect("encode endpoint shared"),
        endpoint.created_at_ms,
    )
}

fn make_signed_fact(
    signer_id: [u8; 32],
    private_key: [u8; 32],
    payload: Vec<u8>,
    timestamp: u64,
) -> Fact {
    let bytes = identity::signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
        .expect("sign fact");
    Fact::new(FactScope::Global, timestamp, bytes)
}

fn deletion_fact(workspace_id: [u8; 32], target_id: [u8; 32]) -> Fact {
    deletion_fact_by_author(
        workspace_id,
        target_id,
        default_author_fact(workspace_id).id,
    )
}

fn deletion_fact_by_author(
    workspace_id: [u8; 32],
    target_id: [u8; 32],
    author_user_id: [u8; 32],
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        2,
        message_deletion_layout::encode_fact(&ContentMessageDeletionFact {
            workspace_id,
            created_at_ms: 2,
            target_message_id: target_id,
            author_user_id,
        })
        .expect("encode deletion"),
    )
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
    find_put_row(intents, table).unwrap_or_else(|| panic!("missing put_row for {}", table.as_str()))
}

fn find_put_row(
    intents: &[topo::core::intents::Intent],
    table: topo::core::store::TableName,
) -> Option<topo::core::store::TableRow> {
    intents.iter().find_map(|intent| {
        if let Ok(AtomicIntent::PutRow(row)) = AtomicIntent::from_intent(intent, &[table]) {
            return Some(row);
        }
        None
    })
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

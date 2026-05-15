use topo::core::event_bus::EventBus;
use topo::core::facts::Fact;
use topo::core::intents::AtomicIntent;
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::event_modules::encryption::context::{
    self as encryption_context, frontier_role, recipient_key_role, recipient_superseded_role,
    WrapSourceKind, WrapSourceMatcher,
};
use topo::event_modules::encryption::fact::{
    KeyRequestFact, LocalHistoryNodeSecretFact, LocalKeySecretFact, RecipientKeyFact,
    RemovalFrontierFact, NO_PREVIOUS_RECIPIENT_KEY,
};
use topo::event_modules::encryption::intent::{
    decode_materialize_key_wraps_intent, decode_purge_retired_recipient_material_intent,
};
use topo::event_modules::encryption::{layout as encryption_layout, project as encryption_project};
use topo::event_modules::sealed_message::context::{
    self as message_context, workspace_scope, SecretCoverageMatcher,
};
use topo::event_modules::sealed_message::fact::{
    SealedMessageFact, SignerPubkeyFact, CIPHERTEXT_BYTES,
};
use topo::event_modules::sealed_message::rows::{MESSAGE_ROWS, SEALED_MESSAGE_ROWS};
use topo::event_modules::sealed_message::{layout as message_layout, project as message_project};

#[test]
fn recipient_key_triggers_proactive_deterministic_wrap_when_frontier_source_appears() {
    let workspace = [1; 32];
    let endpoint = [2; 32];
    let recipient = recipient_key_fact(workspace, endpoint, NO_PREVIOUS_RECIPIENT_KEY, 10);
    let root = local_key_secret_fact(workspace, [3; 32], endpoint, 20);
    let mut bus = EventBus::new();
    let projector = encryption_project::EncryptionProjector::new();
    let wrap_matcher = WrapSourceMatcher::new();

    bus.submit_fact(recipient.clone());
    let waiting = bus
        .drain(&projector, &[&wrap_matcher as &dyn ContextMatcher], 10)
        .expect("recipient waits for source");
    assert_eq!(waiting.intents, 0);
    assert_eq!(bus.context(&recipient.id).unwrap().needs.len(), 2);

    bus.submit_fact(root.clone());
    let wrapped = bus
        .drain(&projector, &[&wrap_matcher as &dyn ContextMatcher], 10)
        .expect("root source wakes recipient");

    assert_eq!(wrapped.wakes, 1);
    assert_eq!(bus.intents().len(), 1);
    let intent = decode_materialize_key_wraps_intent(&bus.intents()[0]).expect("wrap intent");
    assert_eq!(intent.workspace_id, workspace);
    assert_eq!(intent.frontier_id, [3; 32]);
    assert_eq!(intent.recipient_key_id, recipient.id);
    assert_eq!(intent.source, WrapSourceKind::FrontierRoot);
}

#[test]
fn rotated_recipient_key_does_not_receive_old_frontier_sources() {
    let workspace = [4; 32];
    let endpoint = [5; 32];
    let old_frontier = [6; 32];
    let new_frontier = [7; 32];
    let rotated = recipient_key_fact(workspace, endpoint, [8; 32], 50);
    let old_root = local_key_secret_fact(workspace, old_frontier, endpoint, 20);
    let new_root = local_key_secret_fact(workspace, new_frontier, endpoint, 70);
    let projector = encryption_project::EncryptionProjector::new();
    let wrap_matcher = WrapSourceMatcher::new();
    let mut bus = EventBus::new();

    bus.submit_fact(rotated.clone());
    bus.submit_fact(old_root);
    let old_seen = bus
        .drain(&projector, &[&wrap_matcher as &dyn ContextMatcher], 10)
        .expect("old root is not eligible");
    assert_eq!(old_seen.wakes, 0);
    assert!(bus.intents().is_empty());

    bus.submit_fact(new_root);
    let new_seen = bus
        .drain(&projector, &[&wrap_matcher as &dyn ContextMatcher], 10)
        .expect("new root wakes rotated key");
    assert_eq!(new_seen.wakes, 1);
    assert_eq!(bus.intents().len(), 1);
    let intent = decode_materialize_key_wraps_intent(&bus.intents()[0]).expect("wrap intent");
    assert_eq!(intent.frontier_id, new_frontier);
}

#[test]
fn duplicate_key_requests_converge_on_one_wrap_intent_without_request_entropy() {
    let workspace = [10; 32];
    let requester = [11; 32];
    let responder = [12; 32];
    let frontier = removal_frontier_fact(workspace, responder, 10);
    let recipient = recipient_key_fact(workspace, requester, [13; 32], 50);
    let root = local_key_secret_fact(workspace, frontier.id, responder, 10);
    let request_a = key_request_fact(
        workspace,
        requester,
        responder,
        frontier.id,
        recipient.id,
        60,
    );
    let request_b = key_request_fact(
        workspace,
        requester,
        responder,
        frontier.id,
        recipient.id,
        61,
    );
    let projector = encryption_project::EncryptionProjector::new();
    let recipient_matcher = ExactSelectorMatcher::new(recipient_key_role());
    let frontier_matcher = ExactSelectorMatcher::new(frontier_role());
    let superseded_matcher = ExactSelectorMatcher::new(recipient_superseded_role());
    let wrap_matcher = WrapSourceMatcher::new();
    let matchers = [
        &recipient_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &superseded_matcher as &dyn ContextMatcher,
        &wrap_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    for fact in [frontier, recipient, root, request_a, request_b] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 100)
        .expect("duplicate requests drain");

    assert_eq!(
        bus.intents().len(),
        1,
        "duplicate request facts and proactive reconcile must converge on one edge"
    );
    let intent = decode_materialize_key_wraps_intent(&bus.intents()[0]).expect("wrap intent");
    assert_eq!(
        intent.recipient_key_id,
        recipient_key_fact(workspace, requester, [13; 32], 50).id
    );
    assert_eq!(intent.source, WrapSourceKind::FrontierRoot);
}

#[test]
fn post_deletion_key_request_wraps_retained_nodes_without_resurrecting_root() {
    let workspace = [20; 32];
    let requester = [21; 32];
    let responder = [22; 32];
    let frontier = removal_frontier_fact(workspace, responder, 10);
    let recipient = recipient_key_fact(workspace, requester, [23; 32], 80);
    let request = key_request_fact(
        workspace,
        requester,
        responder,
        frontier.id,
        recipient.id,
        90,
    );
    let retained_a = history_node_fact(workspace, frontier.id, 40, 50, 0, [0; 32]);
    let retained_b = history_node_fact(workspace, frontier.id, 51, 60, 1, [0xaa; 32]);
    let projector = encryption_project::EncryptionProjector::new();
    let recipient_matcher = ExactSelectorMatcher::new(recipient_key_role());
    let frontier_matcher = ExactSelectorMatcher::new(frontier_role());
    let wrap_matcher = WrapSourceMatcher::new();
    let matchers = [
        &recipient_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &wrap_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    for fact in [frontier, recipient, request, retained_a, retained_b] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 100)
        .expect("retained nodes satisfy request");

    assert_eq!(bus.intents().len(), 2);
    let intents = bus
        .intents()
        .iter()
        .map(decode_materialize_key_wraps_intent)
        .collect::<Result<Vec<_>, _>>()
        .expect("decode wrap intents");
    assert!(intents
        .iter()
        .all(|intent| matches!(intent.source, WrapSourceKind::HistoryNode { .. })));
}

#[test]
fn supersession_wakes_old_recipient_key_and_purges_material_instead_of_wrapping() {
    let workspace = [30; 32];
    let endpoint = [31; 32];
    let old = recipient_key_fact(workspace, endpoint, NO_PREVIOUS_RECIPIENT_KEY, 10);
    let new = recipient_key_fact(workspace, endpoint, old.id, 20);
    let future_root = local_key_secret_fact(workspace, [32; 32], endpoint, 30);
    let projector = encryption_project::EncryptionProjector::new();
    let superseded_matcher = ExactSelectorMatcher::new(recipient_superseded_role());
    let wrap_matcher = WrapSourceMatcher::new();
    let matchers = [
        &superseded_matcher as &dyn ContextMatcher,
        &wrap_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    bus.submit_fact(old.clone());
    bus.drain(&projector, &matchers, 10).expect("old active");
    bus.submit_fact(new);
    bus.submit_fact(future_root);
    bus.drain(&projector, &matchers, 100)
        .expect("supersession and future source drain");

    let retired = bus
        .intents()
        .iter()
        .filter(|intent| decode_purge_retired_recipient_material_intent(intent).is_ok())
        .count();
    let materialized_for_old = bus
        .intents()
        .iter()
        .filter_map(|intent| decode_materialize_key_wraps_intent(intent).ok())
        .filter(|intent| intent.recipient_key_id == old.id)
        .count();

    assert_eq!(retired, 1);
    assert_eq!(materialized_for_old, 0);
}

#[test]
fn encryption_history_node_offer_wakes_and_opens_sealed_message() {
    let workspace = [40; 32];
    let signer = [41; 32];
    let frontier = [42; 32];
    let leaf = [0xab; 32];
    let message = sealed_message_fact(workspace, signer, frontier, 55, leaf);
    let signer = signer_fact(workspace, signer);
    let history_node = history_node_fact(workspace, frontier, 50, 60, 1, leaf);
    let projector = CombinedProjector;
    let signer_matcher = ExactSelectorMatcher::new(message_context::signer_role());
    let deletion_matcher = ExactSelectorMatcher::new(message_context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &signer_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    bus.submit_fact(message.clone());
    bus.submit_fact(signer);
    bus.submit_fact(history_node);
    bus.drain(&projector, &matchers, 100)
        .expect("history node opens message");

    let rows = bus
        .intents()
        .iter()
        .filter_map(|intent| {
            AtomicIntent::from_intent(intent, &[MESSAGE_ROWS, SEALED_MESSAGE_ROWS]).ok()
        })
        .collect::<Vec<_>>();
    assert!(rows
        .iter()
        .any(|intent| matches!(intent, AtomicIntent::PutRow(row) if row.table == MESSAGE_ROWS && row.key == message.id)));
}

#[test]
fn recipient_key_projector_revalidates_wrap_source_context_before_wrapping() {
    let workspace = [50; 32];
    let endpoint = [51; 32];
    let rotated = recipient_key_fact(workspace, endpoint, [52; 32], 50);
    let stale_source = encryption_context::frontier_root_wrap_source_offer(
        [53; 32],
        workspace_scope(workspace),
        workspace,
        [54; 32],
        20,
    );
    let projector = encryption_project::EncryptionProjector::new();

    let output = projector
        .project(&rotated, &ProjectionContext::new(vec![stale_source]))
        .expect("project with mismatched wrap context");

    assert!(
        output
            .needs
            .iter()
            .any(|need| need.role == encryption_context::wrap_source_role()),
        "stale wrap source must leave proactive wrap need standing"
    );
    assert!(
        output
            .intents
            .iter()
            .all(|intent| decode_materialize_key_wraps_intent(intent).is_err()),
        "stale wrap source must not emit a wrap intent"
    );
}

struct CombinedProjector;

impl Projector for CombinedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(encryption_layout::TYPE_RECIPIENT_KEY)
            | Some(encryption_layout::TYPE_REMOVAL_FRONTIER)
            | Some(encryption_layout::TYPE_LOCAL_KEY_SECRET)
            | Some(encryption_layout::TYPE_LOCAL_HISTORY_NODE_SECRET)
            | Some(encryption_layout::TYPE_KEY_REQUEST) => {
                encryption_project::EncryptionProjector::new().project(fact, context)
            }
            _ => message_project::SealedMessageProjector::new().project(fact, context),
        }
    }
}

fn recipient_key_fact(
    workspace_id: [u8; 32],
    endpoint_id: [u8; 32],
    previous_recipient_key_id: [u8; 32],
    created_at_ms: u64,
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        created_at_ms,
        encryption_layout::encode_recipient_key(&RecipientKeyFact {
            workspace_id,
            endpoint_id,
            recipient_key: [0x55; 32],
            previous_recipient_key_id,
            created_at_ms,
        })
        .expect("encode recipient"),
    )
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
    created_at_ms: u64,
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        created_at_ms,
        encryption_layout::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            created_at_ms,
            secret_commitment: [0x66; 32],
        })
        .expect("encode local root"),
    )
}

fn history_node_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    start_minute: u64,
    end_minute: u64,
    prefix_bytes: u8,
    leaf_prefix: [u8; 32],
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        0,
        encryption_layout::encode_local_history_node_secret(&LocalHistoryNodeSecretFact {
            workspace_id,
            frontier_id,
            source_secret_id: [0x77; 32],
            start_minute,
            end_minute,
            prefix_bytes,
            leaf_prefix,
        })
        .expect("encode history node"),
    )
}

fn key_request_fact(
    workspace_id: [u8; 32],
    requester_endpoint_id: [u8; 32],
    responder_endpoint_id: [u8; 32],
    frontier_id: [u8; 32],
    recipient_key_id: [u8; 32],
    created_at_ms: u64,
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        created_at_ms,
        encryption_layout::encode_key_request(&KeyRequestFact {
            workspace_id,
            requester_endpoint_id,
            responder_endpoint_id,
            frontier_id,
            recipient_key_id,
            created_at_ms,
        })
        .expect("encode request"),
    )
}

fn sealed_message_fact(
    workspace_id: [u8; 32],
    signer_id: [u8; 32],
    frontier_id: [u8; 32],
    minute: u64,
    leaf_id: [u8; 32],
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        minute,
        message_layout::encode_sealed_message(&SealedMessageFact {
            workspace_id,
            signer_id,
            frontier_id,
            minute,
            leaf_id,
            ciphertext: vec![0x99; CIPHERTEXT_BYTES.min(4)],
        })
        .expect("encode message"),
    )
}

fn signer_fact(workspace_id: [u8; 32], signer_id: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        0,
        message_layout::encode_signer_pubkey(&SignerPubkeyFact {
            signer_id,
            public_key: [0x88; 32],
        })
        .expect("encode signer"),
    )
}

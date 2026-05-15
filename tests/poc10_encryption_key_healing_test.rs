use topo::core::crypto;
use topo::core::event_bus::EventBus;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::schema_dsl::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::event_modules::encryption::context::{
    self as encryption_context, frontier_role, recipient_key_role, recipient_superseded_role,
    WrapSourceKind, WrapSourceMatcher,
};
use topo::event_modules::encryption::fact::{
    KeyRequestFact, KeyWrapFact, LocalHistoryNodeSecretFact, LocalKeySecretFact,
    LocalRecipientKeyFact, RecipientKeyFact, RemovalFrontierFact, WrappedSecretKind,
    NO_PREVIOUS_RECIPIENT_KEY,
};
use topo::event_modules::encryption::intent::{
    decode_materialize_key_wraps_intent, decode_purge_retired_recipient_material_intent,
    decode_unwrap_key_wrap_intent,
};
use topo::event_modules::encryption::{
    create as encryption_create, layout as encryption_layout, project as encryption_project,
    rows as encryption_rows,
};
use topo::event_modules::sealed_message::context::{
    self as message_context, workspace_scope, SecretCoverageMatcher,
};
use topo::event_modules::sealed_message::fact::{
    SealedMessageFact, SignerPubkeyFact, CIPHERTEXT_BYTES, NONCE_BYTES,
};
use topo::event_modules::sealed_message::rows::{message_key, MESSAGE_ROWS, SEALED_MESSAGE_ROWS};
use topo::event_modules::sealed_message::{layout as message_layout, project as message_project};
use topo::event_modules::signed_fact::{self, fact::LocalSignerSecretFact};
use topo::event_modules::sync::context as sync_context;
use topo::handlers::materialize_key_wraps::MaterializeKeyWrapsHandler;
use topo::handlers::unwrap_key_wrap::UnwrapKeyWrapHandler;

#[test]
fn recipient_key_triggers_proactive_deterministic_wrap_when_frontier_source_appears() {
    let workspace = [1; 32];
    let endpoint = [2; 32];
    let recipient = recipient_key_fact(workspace, endpoint, NO_PREVIOUS_RECIPIENT_KEY, 10);
    let root = local_key_secret_fact(workspace, [3; 32], endpoint, 20);
    let signer = local_signer_secret_fact(workspace, endpoint);
    let mut bus = EventBus::new();
    let projector = CombinedProjector;
    let wrap_matcher = WrapSourceMatcher::new();
    let signer_matcher =
        ExactSelectorMatcher::new(signed_fact::context::local_signer_secret_role());
    let matchers = [
        &wrap_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
    ];

    bus.submit_fact(recipient.clone());
    let waiting = bus
        .drain(&projector, &matchers, 10)
        .expect("recipient waits for source");
    assert_eq!(waiting.intents, 0);
    assert_eq!(bus.context(&recipient.id).unwrap().needs.len(), 2);

    bus.submit_fact(root.clone());
    bus.submit_fact(signer.clone());
    bus.drain(&projector, &matchers, 20)
        .expect("root source wakes recipient");

    assert_eq!(bus.intents().len(), 1);
    let intent = decode_materialize_key_wraps_intent(&bus.intents()[0]).expect("wrap intent");
    assert_eq!(intent.workspace_id, workspace);
    assert_eq!(intent.frontier_id, [3; 32]);
    assert_eq!(intent.recipient_key_id, recipient.id);
    assert_eq!(intent.source_fact_id, root.id);
    assert_eq!(intent.signer_secret_fact_id, signer.id);
    assert_eq!(intent.source, WrapSourceKind::FrontierRoot);
}

#[test]
fn recipient_key_waits_for_local_signer_secret_before_materializing_wrap() {
    let workspace = [1; 32];
    let endpoint = [2; 32];
    let recipient = recipient_key_fact(workspace, endpoint, NO_PREVIOUS_RECIPIENT_KEY, 10);
    let root = local_key_secret_fact(workspace, [3; 32], endpoint, 20);
    let mut bus = EventBus::new();
    let projector = CombinedProjector;
    let wrap_matcher = WrapSourceMatcher::new();
    let signer_matcher =
        ExactSelectorMatcher::new(signed_fact::context::local_signer_secret_role());
    let matchers = [
        &wrap_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
    ];

    bus.submit_fact(recipient.clone());
    bus.submit_fact(root);
    bus.drain(&projector, &matchers, 20)
        .expect("source without signer");

    assert!(bus.intents().is_empty());
    assert!(bus
        .context(&recipient.id)
        .unwrap()
        .needs
        .iter()
        .any(|need| { need.role == signed_fact::context::local_signer_secret_role() }));
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
    let signer = local_signer_secret_fact(workspace, endpoint);
    let projector = CombinedProjector;
    let wrap_matcher = WrapSourceMatcher::new();
    let signer_matcher =
        ExactSelectorMatcher::new(signed_fact::context::local_signer_secret_role());
    let matchers = [
        &wrap_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    bus.submit_fact(rotated.clone());
    bus.submit_fact(old_root);
    let old_seen = bus
        .drain(&projector, &matchers, 10)
        .expect("old root is not eligible");
    assert_eq!(old_seen.wakes, 0);
    assert!(bus.intents().is_empty());

    let new_root_id = new_root.id;
    bus.submit_fact(new_root);
    bus.submit_fact(signer);
    let new_seen = bus
        .drain(&projector, &matchers, 20)
        .expect("new root wakes rotated key");
    assert!(new_seen.wakes >= 1);
    assert_eq!(bus.intents().len(), 1);
    let intent = decode_materialize_key_wraps_intent(&bus.intents()[0]).expect("wrap intent");
    assert_eq!(intent.frontier_id, new_frontier);
    assert_eq!(intent.source_fact_id, new_root_id);
}

#[test]
fn duplicate_key_requests_converge_on_one_wrap_intent_without_request_entropy() {
    let workspace = [10; 32];
    let requester = [11; 32];
    let responder = [12; 32];
    let frontier = removal_frontier_fact(workspace, responder, 10);
    let recipient = recipient_key_fact(workspace, requester, [13; 32], 50);
    let root = local_key_secret_fact(workspace, frontier.id, responder, 10);
    let signer = local_signer_secret_fact(workspace, responder);
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
    let projector = CombinedProjector;
    let recipient_matcher = ExactSelectorMatcher::new(recipient_key_role());
    let frontier_matcher = ExactSelectorMatcher::new(frontier_role());
    let superseded_matcher = ExactSelectorMatcher::new(recipient_superseded_role());
    let wrap_matcher = WrapSourceMatcher::new();
    let signer_matcher =
        ExactSelectorMatcher::new(signed_fact::context::local_signer_secret_role());
    let matchers = [
        &recipient_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &superseded_matcher as &dyn ContextMatcher,
        &wrap_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    for fact in [frontier, recipient, root, signer, request_a, request_b] {
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
fn key_request_materialize_intent_survives_restart_and_projects_signed_wrap() {
    let workspace = [14; 32];
    let requester = [15; 32];
    let responder = [16; 32];
    let frontier = removal_frontier_fact(workspace, responder, 10);
    let recipient = recipient_key_fact(workspace, requester, [17; 32], 50);
    let root = local_key_secret_fact(workspace, frontier.id, responder, 10);
    let signer = local_signer_secret_fact(workspace, responder);
    let signer_pubkey = signer_pubkey_fact(
        workspace,
        responder,
        crypto::ed25519_public_key(&[0x42; 32]),
    );
    let request = key_request_fact(
        workspace,
        requester,
        responder,
        frontier.id,
        recipient.id,
        70,
    );
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE])
        .expect("open core schema store");
    let projector = CombinedProjector;
    let recipient_matcher = ExactSelectorMatcher::new(recipient_key_role());
    let frontier_matcher = ExactSelectorMatcher::new(frontier_role());
    let wrap_matcher = WrapSourceMatcher::new();
    let signer_secret_matcher =
        ExactSelectorMatcher::new(signed_fact::context::local_signer_secret_role());
    let signer_pubkey_matcher = ExactSelectorMatcher::new(message_context::signer_role());
    let matchers = [
        &recipient_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &wrap_matcher as &dyn ContextMatcher,
        &signer_secret_matcher as &dyn ContextMatcher,
        &signer_pubkey_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    for fact in [
        frontier.clone(),
        recipient.clone(),
        root.clone(),
        signer.clone(),
        signer_pubkey,
        request,
    ] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 100)
        .expect("key request emits materialize intent");
    assert_eq!(bus.intents().len(), 1);
    let intent = decode_materialize_key_wraps_intent(&bus.intents()[0]).expect("wrap intent");
    assert_eq!(intent.recipient_key_id, recipient.id);
    assert_eq!(intent.source_fact_id, root.id);
    assert_eq!(intent.signer_secret_fact_id, signer.id);
    bus.save(&store).expect("save bus with pending wrap intent");

    let mut restarted = EventBus::load(&store).expect("load bus with wrap intent");
    assert_eq!(restarted.intents().len(), 1);
    let expected_signed_wrap =
        encryption_create::materialize_signed_key_wrap_fact(&intent, &recipient, &root, &signer)
            .expect("materialize expected signed wrap");
    let dispatch = restarted
        .dispatch_deferred_intents_with_fact_context(&MaterializeKeyWrapsHandler::new(), 10)
        .expect("dispatch materialize handler after restart");

    assert_eq!(dispatch.handled, 1);
    assert_eq!(dispatch.facts, 1);
    assert!(restarted.intents().is_empty());
    assert!(restarted.has_fact(&expected_signed_wrap.id));

    restarted
        .drain(&projector, &matchers, 100)
        .expect("project signed key wrap");
    let signed_context = restarted
        .context(&expected_signed_wrap.id)
        .expect("signed wrap projected context");
    assert!(signed_context.offers.iter().any(|offer| {
        offer.role == sync_context::key_wrap_role()
            && offer.selector.as_bytes() == expected_signed_wrap.id
            && offer.payload_ref == expected_signed_wrap.id
    }));
    assert!(signed_context.offers.iter().any(|offer| {
        offer.role == sync_context::exact_event_role()
            && offer.selector.as_bytes() == expected_signed_wrap.id
            && offer.payload_ref == expected_signed_wrap.id
    }));
    assert!(signed_context.needs.iter().any(|need| {
        need.role == encryption_context::local_recipient_key_role()
            && need.selector.as_bytes() == recipient.id
    }));
    assert!(!signed_context
        .offers
        .iter()
        .any(|offer| offer.role == message_context::secret_role()));

    let envelope =
        signed_fact::layout::decode_signed_fact(&expected_signed_wrap.bytes).expect("signed wrap");
    assert_eq!(envelope.signer_id, responder);
    assert_eq!(
        envelope.signer_public_key,
        crypto::ed25519_public_key(&[0x42; 32])
    );
    let wrap = encryption_layout::decode_key_wrap(&envelope.payload).expect("key wrap payload");
    assert_eq!(wrap.wrapped_secret_kind, WrappedSecretKind::FrontierRoot);
    assert_eq!(wrap.wrapped_secret_id, root.id);
    assert_eq!(wrap.recipient_key_id, recipient.id);
    assert!(wrap.sender_wrap_public_key.iter().any(|byte| *byte != 0));
    assert!(wrap.nonce.iter().any(|byte| *byte != 0));
    assert_ne!(wrap.ciphertext, [0x66; 48]);
    let rows = restarted
        .intents()
        .iter()
        .filter_map(|intent| {
            AtomicIntent::from_intent(intent, &[encryption_rows::KEY_WRAP_ROWS]).ok()
        })
        .collect::<Vec<_>>();
    let row = rows
        .iter()
        .find_map(|intent| match intent {
            AtomicIntent::PutRow(row) if row.table == encryption_rows::KEY_WRAP_ROWS => Some(row),
            _ => None,
        })
        .expect("accepted key wrap row intent");
    let decoded = encryption_rows::decode_key_wrap_row(&row.key, &row.value)
        .expect("decode accepted key wrap row");
    assert_eq!(decoded.key_wrap_id, expected_signed_wrap.id);
    assert_eq!(decoded.wrap.recipient_key_id, recipient.id);
    assert_eq!(decoded.wrap.frontier_id, frontier.id);

    restarted
        .save(&store)
        .expect("save after dispatch and projection");
    let loaded = EventBus::load(&store).expect("reload after dispatch");
    assert_eq!(loaded.intents().len(), 1);
    assert!(loaded.context(&expected_signed_wrap.id).is_some());
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
    let retained_a = history_node_fact(workspace, frontier.id, 40, 8, 0, [0; 32]);
    let retained_b = history_node_fact(workspace, frontier.id, 51, 1, 8, byte_prefix(0xaa));
    let signer = local_signer_secret_fact(workspace, [0x76; 32]);
    let projector = CombinedProjector;
    let recipient_matcher = ExactSelectorMatcher::new(recipient_key_role());
    let frontier_matcher = ExactSelectorMatcher::new(frontier_role());
    let wrap_matcher = WrapSourceMatcher::new();
    let signer_matcher =
        ExactSelectorMatcher::new(signed_fact::context::local_signer_secret_role());
    let matchers = [
        &recipient_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &wrap_matcher as &dyn ContextMatcher,
        &signer_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    for fact in [frontier, recipient, request, retained_a, retained_b, signer] {
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
fn encryption_history_node_offer_wakes_and_clears_sealed_message_secret_need() {
    let workspace = [40; 32];
    let signer = [41; 32];
    let frontier = [42; 32];
    let leaf = [0xab; 32];
    let message = sealed_message_fact(workspace, signer, frontier, 55, leaf);
    let signer = signer_fact(workspace, signer);
    let history_node = history_node_fact(workspace, frontier, 55, 1, 8, byte_prefix(0xab));
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
        .expect("history node covers message");

    let rows = bus
        .intents()
        .iter()
        .filter_map(|intent| {
            AtomicIntent::from_intent(intent, &[MESSAGE_ROWS, SEALED_MESSAGE_ROWS]).ok()
        })
        .collect::<Vec<_>>();
    assert!(rows
        .iter()
        .any(|intent| matches!(intent, AtomicIntent::PutRow(row) if row.table == SEALED_MESSAGE_ROWS && row.key == message_key(workspace, message.id))));
    assert!(!rows
        .iter()
        .any(|intent| matches!(intent, AtomicIntent::PutRow(row) if row.table == MESSAGE_ROWS)));
    let context = bus
        .context(&message.id)
        .expect("message keeps deletion context");
    assert!(!context
        .needs
        .iter()
        .any(|need| need.role == message_context::secret_role()));
}

#[test]
fn signed_key_wrap_waits_for_context_then_offers_sync_key_and_row() {
    let workspace = [43; 32];
    let signer_id = [44; 32];
    let signer_private_key = [45; 32];
    let frontier = removal_frontier_fact(workspace, signer_id, 9);
    let recipient = recipient_key_fact(workspace, signer_id, NO_PREVIOUS_RECIPIENT_KEY, 9);
    let signed_wrap = signed_key_wrap_fact(
        workspace,
        signer_id,
        signer_private_key,
        frontier.id,
        recipient.id,
    );
    let signer = signer_pubkey_fact(
        workspace,
        signer_id,
        crypto::ed25519_public_key(&signer_private_key),
    );
    let signer_matcher = ExactSelectorMatcher::new(message_context::signer_role());
    let recipient_matcher = ExactSelectorMatcher::new(recipient_key_role());
    let frontier_matcher = ExactSelectorMatcher::new(frontier_role());
    let matchers = [
        &signer_matcher as &dyn ContextMatcher,
        &recipient_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    bus.submit_fact(signed_wrap.clone());
    bus.drain(&CombinedProjector, &matchers, 10)
        .expect("signed wrap waits for authority and exact context");

    let waiting = bus.context(&signed_wrap.id).expect("waiting context");
    assert!(waiting
        .needs
        .iter()
        .any(|need| need.role == message_context::signer_role()
            && need.selector.as_bytes() == signer_id));
    assert!(waiting
        .needs
        .iter()
        .any(|need| need.role == recipient_key_role() && need.selector.as_bytes() == recipient.id));
    assert!(waiting
        .needs
        .iter()
        .any(|need| need.role == frontier_role() && need.selector.as_bytes() == frontier.id));
    assert!(waiting.offers.is_empty());

    bus.submit_fact(signer);
    bus.drain(&CombinedProjector, &matchers, 10)
        .expect("signer alone is not enough");
    let still_waiting = bus.context(&signed_wrap.id).expect("still waiting");
    assert!(still_waiting
        .needs
        .iter()
        .any(|need| need.role == recipient_key_role()));
    assert!(still_waiting
        .needs
        .iter()
        .any(|need| need.role == frontier_role()));

    bus.submit_fact(frontier.clone());
    bus.submit_fact(recipient.clone());
    let report = bus
        .drain(&CombinedProjector, &matchers, 10)
        .expect("full context wakes signed key wrap");

    assert!(report.wakes >= 1);
    let ready = bus
        .context(&signed_wrap.id)
        .expect("ready key-wrap context");
    assert!(ready.offers.iter().any(|offer| {
        offer.role == sync_context::key_wrap_role()
            && offer.selector.as_bytes() == signed_wrap.id
            && offer.payload_ref == signed_wrap.id
    }));
    assert!(ready.offers.iter().any(|offer| {
        offer.role == sync_context::exact_event_role()
            && offer.selector.as_bytes() == signed_wrap.id
            && offer.payload_ref == signed_wrap.id
    }));
    let rows = bus
        .intents()
        .iter()
        .filter_map(|intent| {
            AtomicIntent::from_intent(intent, &[encryption_rows::KEY_WRAP_ROWS]).ok()
        })
        .collect::<Vec<_>>();
    let row = rows
        .iter()
        .find_map(|intent| match intent {
            AtomicIntent::PutRow(row) if row.table == encryption_rows::KEY_WRAP_ROWS => Some(row),
            _ => None,
        })
        .expect("accepted key wrap row");
    let decoded = encryption_rows::decode_key_wrap_row(&row.key, &row.value)
        .expect("decode accepted key wrap row");
    assert_eq!(decoded.key_wrap_id, signed_wrap.id);
    assert_eq!(decoded.wrap.frontier_id, frontier.id);
    assert_eq!(decoded.wrap.recipient_key_id, recipient.id);
    assert!(
        !ready
            .offers
            .iter()
            .any(|offer| offer.role == message_context::secret_role()),
        "an accepted signed key wrap is not message-secret coverage by itself"
    );
    assert!(
        ready.needs.iter().any(|need| {
            need.role == encryption_context::local_recipient_key_role()
                && need.selector.as_bytes() == recipient.id
        }),
        "accepted key wraps should wait for local recipient material before unwrapping"
    );
}

#[test]
fn local_recipient_key_wakes_signed_wrap_unwrap_and_covers_sealed_message() {
    let workspace = [70; 32];
    let signer_id = [71; 32];
    let signer_private_key = [72; 32];
    let frontier = removal_frontier_fact(workspace, signer_id, 10);
    let root = local_key_secret_fact(workspace, frontier.id, signer_id, 10);
    let recipient_secret = [73; 32];
    let recipient_public = crypto::x25519_public_key(&recipient_secret);
    let recipient =
        recipient_key_fact_with_public(workspace, signer_id, recipient_public, [0; 32], 11);
    let local_recipient =
        local_recipient_key_fact(workspace, recipient.id, recipient_public, recipient_secret);
    let signer = local_signer_secret_fact_with_private(workspace, signer_id, signer_private_key);
    let signer_pubkey = signer_pubkey_fact(
        workspace,
        signer_id,
        crypto::ed25519_public_key(&signer_private_key),
    );
    let materialize = decode_materialize_key_wraps_intent(
        &topo::event_modules::encryption::intent::materialize_key_wraps_intent(
            recipient.id,
            root.id,
            signer.id,
            encryption_context::WrapSourceSelector {
                workspace_id: workspace,
                frontier_id: frontier.id,
                owner_endpoint_id: signer_id,
                frontier_created_at_ms: 10,
                kind: WrapSourceKind::FrontierRoot,
            },
        ),
    )
    .expect("decode materialize intent");
    let signed_wrap = encryption_create::materialize_signed_key_wrap_fact(
        &materialize,
        &recipient,
        &root,
        &signer,
    )
    .expect("materialize signed key wrap");
    let message = sealed_message_fact(workspace, signer_id, frontier.id, 15, [74; 32]);
    let projector = CombinedProjector;
    let signer_matcher = ExactSelectorMatcher::new(message_context::signer_role());
    let recipient_matcher = ExactSelectorMatcher::new(recipient_key_role());
    let frontier_matcher = ExactSelectorMatcher::new(frontier_role());
    let local_recipient_matcher =
        ExactSelectorMatcher::new(encryption_context::local_recipient_key_role());
    let deletion_matcher = ExactSelectorMatcher::new(message_context::deletion_role());
    let secret_matcher = SecretCoverageMatcher::new();
    let matchers = [
        &signer_matcher as &dyn ContextMatcher,
        &recipient_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
        &local_recipient_matcher as &dyn ContextMatcher,
        &deletion_matcher as &dyn ContextMatcher,
        &secret_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    for fact in [
        signed_wrap.clone(),
        signer_pubkey,
        frontier.clone(),
        recipient.clone(),
        message.clone(),
    ] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 100)
        .expect("accepted wrap and sealed message project without local recipient");
    let wrap_context = bus.context(&signed_wrap.id).expect("signed wrap context");
    assert!(wrap_context.offers.iter().any(|offer| {
        offer.role == sync_context::key_wrap_role()
            && offer.selector.as_bytes() == signed_wrap.id
            && offer.payload_ref == signed_wrap.id
    }));
    assert!(
        !wrap_context
            .offers
            .iter()
            .any(|offer| offer.role == message_context::secret_role()),
        "accepted key wrap must not masquerade as local secret coverage"
    );
    let message_context_before = bus.context(&message.id).expect("message waits for secret");
    assert!(message_context_before
        .needs
        .iter()
        .any(|need| need.role == message_context::secret_role()));
    assert!(
        !message_rows(&bus)
            .iter()
            .any(|row| row.key == message_key(workspace, message.id)),
        "sealed message must not materialize plaintext before local unwrap"
    );

    bus.submit_fact(local_recipient.clone());
    bus.drain(&projector, &matchers, 100)
        .expect("local recipient wakes signed key wrap");
    let unwrap = bus
        .intents()
        .iter()
        .find_map(|intent| decode_unwrap_key_wrap_intent(intent).ok())
        .expect("local recipient context emits unwrap_key_wrap intent");
    assert_eq!(unwrap.workspace_id, workspace);
    assert_eq!(unwrap.frontier_id, frontier.id);
    assert_eq!(unwrap.recipient_key_id, recipient.id);
    assert_eq!(unwrap.key_wrap_id, signed_wrap.id);
    assert_eq!(unwrap.local_recipient_key_id, local_recipient.id);

    let dispatch = bus
        .dispatch_deferred_intents_with_fact_context(&UnwrapKeyWrapHandler::new(), 10)
        .expect("dispatch unwrap handler");
    assert_eq!(dispatch.handled, 1);
    assert_eq!(dispatch.facts, 1);
    assert!(bus.has_fact(&root.id));
    bus.drain(&projector, &matchers, 100)
        .expect("unwrapped root offers normal secret coverage");

    let message_context_after = bus
        .context(&message.id)
        .expect("covered message keeps deletion context");
    assert!(!message_context_after
        .needs
        .iter()
        .any(|need| need.role == message_context::secret_role()));
    assert!(
        !message_rows(&bus)
            .iter()
            .any(|row| row.key == message_key(workspace, message.id)),
        "secret coverage alone must not fake a plaintext row"
    );
}

#[test]
fn signed_key_wrap_rejects_signer_public_key_mismatch() {
    let workspace = [46; 32];
    let signer_id = [47; 32];
    let signer_private_key = [48; 32];
    let frontier = removal_frontier_fact(workspace, signer_id, 9);
    let recipient = recipient_key_fact(workspace, signer_id, NO_PREVIOUS_RECIPIENT_KEY, 9);
    let signed_wrap = signed_key_wrap_fact(
        workspace,
        signer_id,
        signer_private_key,
        frontier.id,
        recipient.id,
    );
    let wrong_signer =
        signer_pubkey_fact(workspace, signer_id, crypto::ed25519_public_key(&[49; 32]));
    let signer_matcher = ExactSelectorMatcher::new(message_context::signer_role());
    let recipient_matcher = ExactSelectorMatcher::new(recipient_key_role());
    let frontier_matcher = ExactSelectorMatcher::new(frontier_role());
    let matchers = [
        &signer_matcher as &dyn ContextMatcher,
        &recipient_matcher as &dyn ContextMatcher,
        &frontier_matcher as &dyn ContextMatcher,
    ];
    let mut bus = EventBus::new();

    bus.submit_fact(signed_wrap.clone());
    bus.submit_fact(wrong_signer);
    bus.submit_fact(frontier);
    bus.submit_fact(recipient);
    bus.drain(&CombinedProjector, &matchers, 10)
        .expect("wrong signer pubkey is not authority");

    let context = bus.context(&signed_wrap.id).expect("still waiting");
    assert!(context
        .needs
        .iter()
        .any(|need| need.role == message_context::signer_role()));
    assert!(!context
        .offers
        .iter()
        .any(|offer| offer.role == sync_context::key_wrap_role()));
}

#[test]
fn signed_key_wrap_rejects_envelope_signer_mismatch() {
    let workspace = [50; 32];
    let wrap_signer = [51; 32];
    let envelope_signer = [52; 32];
    let payload = encryption_layout::encode_key_wrap(&key_wrap_fact(
        workspace,
        wrap_signer,
        [54; 32],
        [55; 32],
    ))
    .expect("encode key wrap");
    let bytes = signed_fact::create::sign_payload_bytes(envelope_signer, &[53; 32], payload)
        .expect("sign key wrap");
    let fact = Fact::new(workspace_scope(workspace), 10, bytes);

    let err = encryption_project::EncryptionProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect_err("envelope signer mismatch must fail");

    assert!(err.contains("key wrap signer does not match signed envelope signer"));
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
        endpoint,
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
            | Some(encryption_layout::TYPE_LOCAL_RECIPIENT_KEY)
            | Some(encryption_layout::TYPE_KEY_REQUEST)
            | Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
                encryption_project::EncryptionProjector::new().project(fact, context)
            }
            Some(signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET) => {
                signed_fact::project::SignedFactProjector::new().project(fact, context)
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
    recipient_key_fact_with_public(
        workspace_id,
        endpoint_id,
        [0x55; 32],
        previous_recipient_key_id,
        created_at_ms,
    )
}

fn recipient_key_fact_with_public(
    workspace_id: [u8; 32],
    endpoint_id: [u8; 32],
    recipient_key: [u8; 32],
    previous_recipient_key_id: [u8; 32],
    created_at_ms: u64,
) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        created_at_ms,
        encryption_layout::encode_recipient_key(&RecipientKeyFact {
            workspace_id,
            endpoint_id,
            recipient_key,
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
        FactScope::Local,
        created_at_ms,
        encryption_layout::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            created_at_ms,
            key_secret: [0x66; 32],
        })
        .expect("encode local root"),
    )
}

fn history_node_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: [u8; 32],
) -> Fact {
    Fact::new(
        FactScope::Local,
        0,
        encryption_layout::encode_local_history_node_secret(&LocalHistoryNodeSecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id: [0x76; 32],
            source_secret_id: [0x77; 32],
            range_start,
            range_width,
            bit_depth,
            event_id_prefix,
            tombstone_node_id: [0x78; 32],
            node_secret: [0x79; 32],
        })
        .expect("encode history node"),
    )
}

fn local_signer_secret_fact(workspace_id: [u8; 32], signer_id: [u8; 32]) -> Fact {
    local_signer_secret_fact_with_private(workspace_id, signer_id, [0x42; 32])
}

fn local_signer_secret_fact_with_private(
    workspace_id: [u8; 32],
    signer_id: [u8; 32],
    private_key: [u8; 32],
) -> Fact {
    Fact::new(
        FactScope::Local,
        0,
        signed_fact::layout::encode_local_signer_secret(&LocalSignerSecretFact {
            workspace_id,
            signer_id,
            public_key: topo::core::crypto::ed25519_public_key(&private_key),
            private_key,
        })
        .expect("encode local signer secret"),
    )
}

fn local_recipient_key_fact(
    workspace_id: [u8; 32],
    recipient_key_id: [u8; 32],
    recipient_key: [u8; 32],
    recipient_secret: [u8; 32],
) -> Fact {
    Fact::new(
        FactScope::Local,
        0,
        encryption_layout::encode_local_recipient_key(&LocalRecipientKeyFact {
            workspace_id,
            recipient_key_id,
            recipient_key,
            recipient_secret,
        })
        .expect("encode local recipient key"),
    )
}

fn message_rows(bus: &EventBus) -> Vec<topo::core::store::TableRow> {
    bus.intents()
        .iter()
        .filter_map(|intent| AtomicIntent::from_intent(intent, &[MESSAGE_ROWS]).ok())
        .filter_map(|intent| match intent {
            AtomicIntent::PutRow(row) if row.table == MESSAGE_ROWS => Some(row),
            _ => None,
        })
        .collect()
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
            created_at_ms: minute * 60_000,
            author_user_id: [0xa1; 32],
            signer_id,
            frontier_id,
            local_history_node_secret_id: [0xa2; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [0xa3; 32],
            minute,
            leaf_id,
            nonce: [0xa4; NONCE_BYTES],
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

fn signer_pubkey_fact(workspace_id: [u8; 32], signer_id: [u8; 32], public_key: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        0,
        message_layout::encode_signer_pubkey(&SignerPubkeyFact {
            signer_id,
            public_key,
        })
        .expect("encode signer"),
    )
}

fn signed_key_wrap_fact(
    workspace_id: [u8; 32],
    signer_id: [u8; 32],
    signer_private_key: [u8; 32],
    frontier_id: [u8; 32],
    recipient_key_id: [u8; 32],
) -> Fact {
    let payload = encryption_layout::encode_key_wrap(&key_wrap_fact(
        workspace_id,
        signer_id,
        frontier_id,
        recipient_key_id,
    ))
    .expect("encode key wrap");
    let bytes = signed_fact::create::sign_payload_bytes(signer_id, &signer_private_key, payload)
        .expect("sign key wrap");
    Fact::new(workspace_scope(workspace_id), 10, bytes)
}

fn key_wrap_fact(
    workspace_id: [u8; 32],
    signer_id: [u8; 32],
    frontier_id: [u8; 32],
    recipient_key_id: [u8; 32],
) -> KeyWrapFact {
    KeyWrapFact {
        workspace_id,
        created_at_ms: 10,
        signer_endpoint_id: signer_id,
        frontier_id,
        wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
        wrapped_secret_id: [0x54; 32],
        wrapped_source_secret_id: [0; 32],
        wrapped_tombstone_node_id: [0; 32],
        range_start: 0,
        range_width: 0,
        bit_depth: 0,
        event_id_prefix: [0; 32],
        recipient_key_id,
        sender_wrap_public_key: [0x56; 32],
        nonce: [0x57; 24],
        ciphertext: [0x58; 48],
    }
}

fn byte_prefix(value: u8) -> [u8; 32] {
    let mut prefix = [0; 32];
    prefix[0] = value;
    prefix
}

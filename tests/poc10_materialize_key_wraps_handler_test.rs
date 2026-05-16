use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::core::wake_loop::WakeLoop;
use topo::event_modules::encryption::fact::{
    LocalKeySecretFact, RecipientKeyFact, WrappedSecretKind, NO_PREVIOUS_RECIPIENT_KEY,
};
use topo::event_modules::encryption::intent;
use topo::event_modules::encryption::layout;
use topo::event_modules::encryption::matchers::{
    workspace_scope, WrapSourceKind, WrapSourceSelector,
};
use topo::event_modules::signed_fact::{self, fact::LocalSignerSecretFact};
use topo::handlers::materialize_key_wraps::MaterializeKeyWrapsHandler;

#[test]
fn handler_materializes_real_root_key_wrap_from_exact_fact_context() {
    let workspace = [1; 32];
    let endpoint = [2; 32];
    let frontier = [3; 32];
    let recipient = recipient_key_fact(workspace, endpoint, [4; 32]);
    let source = local_root_fact(workspace, frontier, endpoint, [5; 32]);
    let signer = local_signer_secret_fact(workspace, endpoint);
    let source_selector = WrapSourceSelector {
        workspace_id: workspace,
        frontier_id: frontier,
        owner_endpoint_id: endpoint,
        frontier_created_at_ms: 10,
        kind: WrapSourceKind::FrontierRoot,
    };
    let materialize =
        intent::materialize_key_wraps_intent(recipient.id, source.id, signer.id, source_selector);
    let handler = MaterializeKeyWrapsHandler::new();
    let context = HandlerContext::with_facts([recipient.clone(), source.clone(), signer.clone()]);

    let first = handler
        .handle(&materialize, &context)
        .expect("materialize first wrap");
    let second = handler
        .handle(&materialize, &context)
        .expect("materialize second wrap");

    assert_eq!(first.facts.len(), 1);
    assert_eq!(first.facts, second.facts);
    let envelope = signed_fact::layout::decode_signed_fact(&first.facts[0].bytes)
        .expect("decode signed key wrap");
    assert_eq!(envelope.signer_id, endpoint);
    assert_eq!(envelope.inner_type, layout::TYPE_KEY_WRAP);
    let wrap = layout::decode_key_wrap(&envelope.payload).expect("decode key wrap");
    assert_eq!(wrap.workspace_id, workspace);
    assert_eq!(wrap.signer_endpoint_id, endpoint);
    assert_eq!(wrap.frontier_id, frontier);
    assert_eq!(wrap.wrapped_secret_kind, WrappedSecretKind::FrontierRoot);
    assert_eq!(wrap.wrapped_secret_id, source.id);
    assert_eq!(wrap.wrapped_source_secret_id, [0; 32]);
    assert_eq!(wrap.wrapped_tombstone_node_id, [0; 32]);
    assert_eq!(wrap.recipient_key_id, recipient.id);
    assert!(wrap.sender_wrap_public_key.iter().any(|byte| *byte != 0));
    assert!(wrap.nonce.iter().any(|byte| *byte != 0));
    assert_ne!(wrap.ciphertext, [0; 48]);
    assert_ne!(wrap.ciphertext[..32], [5; 32]);
}

#[test]
fn missing_source_context_leaves_materialize_intent_queued() {
    let workspace = [11; 32];
    let endpoint = [12; 32];
    let frontier = [13; 32];
    let recipient = recipient_key_fact(workspace, endpoint, [14; 32]);
    let missing_source_id = [15; 32];
    let source_selector = WrapSourceSelector {
        workspace_id: workspace,
        frontier_id: frontier,
        owner_endpoint_id: endpoint,
        frontier_created_at_ms: 10,
        kind: WrapSourceKind::FrontierRoot,
    };
    let mut bus = WakeLoop::new();
    let handler = MaterializeKeyWrapsHandler::new();
    let signer = local_signer_secret_fact(workspace, endpoint);
    let materialize = intent::materialize_key_wraps_intent(
        recipient.id,
        missing_source_id,
        signer.id,
        source_selector,
    );

    bus.submit_fact(recipient);
    bus.submit_fact(signer);
    bus.submit_intent(materialize).expect("submit materialize");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect("missing source fact leaves intent queued");

    assert_eq!(report.handled, 0);
    assert_eq!(bus.intents().len(), 1);
}

#[test]
fn missing_signer_context_leaves_materialize_intent_queued() {
    let workspace = [21; 32];
    let endpoint = [22; 32];
    let frontier = [23; 32];
    let recipient = recipient_key_fact(workspace, endpoint, [24; 32]);
    let source = local_root_fact(workspace, frontier, endpoint, [25; 32]);
    let missing_signer_id = [26; 32];
    let source_selector = WrapSourceSelector {
        workspace_id: workspace,
        frontier_id: frontier,
        owner_endpoint_id: endpoint,
        frontier_created_at_ms: 10,
        kind: WrapSourceKind::FrontierRoot,
    };
    let mut bus = WakeLoop::new();
    let handler = MaterializeKeyWrapsHandler::new();
    let materialize = intent::materialize_key_wraps_intent(
        recipient.id,
        source.id,
        missing_signer_id,
        source_selector,
    );

    bus.submit_fact(recipient);
    bus.submit_fact(source);
    bus.submit_intent(materialize).expect("submit materialize");
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&handler, 10)
        .expect("missing signer fact leaves intent queued");

    assert_eq!(report.handled, 0);
    assert_eq!(bus.intents().len(), 1);
}

fn recipient_key_fact(workspace_id: [u8; 32], endpoint_id: [u8; 32], public_key: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        10,
        layout::encode_recipient_key(&RecipientKeyFact {
            workspace_id,
            endpoint_id,
            recipient_key: public_key,
            previous_recipient_key_id: NO_PREVIOUS_RECIPIENT_KEY,
            created_at_ms: 10,
        })
        .expect("encode recipient"),
    )
}

fn local_root_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    owner_endpoint_id: [u8; 32],
    key_secret: [u8; 32],
) -> Fact {
    Fact::new(
        FactScope::Local,
        20,
        layout::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            created_at_ms: 20,
            key_secret,
        })
        .expect("encode local root"),
    )
}

fn local_signer_secret_fact(workspace_id: [u8; 32], signer_id: [u8; 32]) -> Fact {
    let private_key = [9; 32];
    Fact::new(
        FactScope::Local,
        10,
        signed_fact::layout::encode_local_signer_secret(&LocalSignerSecretFact {
            workspace_id,
            signer_id,
            public_key: topo::core::crypto::ed25519_public_key(&private_key),
            private_key,
        })
        .expect("encode signer secret"),
    )
}

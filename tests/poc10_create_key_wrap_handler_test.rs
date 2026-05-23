use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, IntentHandler};
use topo::protocol::auth;
use topo::protocol::auth::create_key_wrap as intent;
use topo::protocol::auth::create_key_wrap::CreateKeyWrapHandler;
use topo::protocol::auth::key_wrap::fact::WrappedSecretKind;
use topo::protocol::auth::key_wrap::layout as key_wrap_layout;
use topo::protocol::auth::key_wrap::project::{WrapSourceDescriptor, WrapSourceKind};
use topo::protocol::auth::local_key_secret::fact::LocalKeySecretFact;
use topo::protocol::auth::local_key_secret::layout as local_key_secret_layout;
use topo::protocol::auth::recipient_key::fact::{RecipientKeyFact, NO_PREVIOUS_RECIPIENT_KEY};
use topo::protocol::auth::recipient_key::layout as recipient_key_layout;
use topo::protocol::auth::signed_fact::fact::LocalSignerSecretFact;
use topo::protocol::auth::workspace::scope as workspace_scope;

#[test]
fn handler_materializes_real_root_key_wrap_from_exact_fact_context() {
    let workspace = [1; 32];
    let endpoint = [2; 32];
    let frontier = [3; 32];
    let recipient = recipient_key_fact(workspace, endpoint, [4; 32]);
    let source = local_root_fact(workspace, frontier, endpoint, [5; 32]);
    let signer = local_signer_secret_fact(workspace, endpoint);
    let source_descriptor = WrapSourceDescriptor {
        workspace_id: workspace,
        frontier_id: frontier,
        owner_endpoint_id: endpoint,
        frontier_created_at_ms: 10,
        kind: WrapSourceKind::FrontierRoot,
    };
    let materialize =
        intent::create_key_wrap_intent(recipient.id, source.id, signer.id, source_descriptor);
    let handler = CreateKeyWrapHandler::new();
    let context = HandlerContext::with_facts([recipient.clone(), source.clone(), signer.clone()]);

    let first = handler
        .handle(&materialize, &context)
        .expect("materialize first wrap");
    let second = handler
        .handle(&materialize, &context)
        .expect("materialize second wrap");

    assert_eq!(first.facts.len(), 1);
    assert_eq!(first.facts, second.facts);
    let envelope = auth::signed_fact::layout::decode_signed_fact(&first.facts[0].bytes)
        .expect("decode signed key wrap");
    assert_eq!(envelope.signer_id, endpoint);
    assert_eq!(envelope.inner_type, key_wrap_layout::TYPE_KEY_WRAP);
    let wrap = key_wrap_layout::decode_key_wrap(&envelope.payload).expect("decode key wrap");
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

fn recipient_key_fact(workspace_id: [u8; 32], endpoint_id: [u8; 32], public_key: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        10,
        recipient_key_layout::encode_recipient_key(&RecipientKeyFact {
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
        local_key_secret_layout::encode_local_key_secret(&LocalKeySecretFact {
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
        auth::signed_fact::layout::encode_local_signer_secret(&LocalSignerSecretFact {
            workspace_id,
            signer_id,
            public_key: topo::core::crypto::ed25519_public_key(&private_key),
            private_key,
        })
        .expect("encode signer secret"),
    )
}

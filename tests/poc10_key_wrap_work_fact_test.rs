use topo::core::context::{ContextNeed, ContextOffer};
use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::project_fact::{MatchedContext, ProjectionContext, Projector};
use topo::protocol::auth::key_wrap::fact::WrappedSecretKind;
use topo::protocol::auth::key_wrap::project::decode as key_wrap_layout;
use topo::protocol::auth::key_wrap::project::{WrapSourceDescriptor, WrapSourceKind};
use topo::protocol::auth::key_wrap_creation::author::key_wrap_creation_fact;
use topo::protocol::auth::key_wrap_creation::project::KeyWrapCreationProjector;
use topo::protocol::auth::key_wrap_recovery::author::key_wrap_recovery_fact;
use topo::protocol::auth::key_wrap_recovery::project::KeyWrapRecoveryProjector;
use topo::protocol::auth::local_key_secret::encode as local_key_secret_layout;
use topo::protocol::auth::local_key_secret::fact::LocalKeySecretFact;
use topo::protocol::auth::local_recipient_key::encode as local_recipient_layout;
use topo::protocol::auth::local_recipient_key::fact::LocalRecipientKeyFact;
use topo::protocol::auth::local_signer_secret::encode as local_signer_layout;
use topo::protocol::auth::local_signer_secret::fact::LocalSignerSecretFact;
use topo::protocol::auth::recipient_key::encode as recipient_key_layout;
use topo::protocol::auth::recipient_key::fact::{RecipientKeyFact, NO_PREVIOUS_RECIPIENT_KEY};
use topo::protocol::auth::removal_frontier::encode as removal_frontier_layout;
use topo::protocol::auth::removal_frontier::fact::RemovalFrontierFact;
use topo::protocol::auth::workspace::scope as workspace_scope;

#[test]
fn key_wrap_work_facts_create_and_recover_root_secret_from_exact_context() {
    let workspace = [1; 32];
    let endpoint = [2; 32];
    let recipient_secret = [4; 32];
    let recipient_public = crypto::x25519_public_key(&recipient_secret);
    let recipient = recipient_key_fact(workspace, endpoint, recipient_public);
    let frontier_fact = removal_frontier_fact(workspace, endpoint);
    let frontier = frontier_fact.id;
    let source = local_root_fact(workspace, frontier, endpoint, [5; 32]);
    let signer = local_signer_secret_fact(workspace, endpoint);
    let local_recipient =
        local_recipient_key_fact(workspace, recipient.id, recipient_public, recipient_secret);
    let source_descriptor = WrapSourceDescriptor {
        workspace_id: workspace,
        frontier_id: frontier,
        owner_endpoint_id: endpoint,
        frontier_created_at_ms: 20,
        kind: WrapSourceKind::FrontierRoot,
    };
    let creation_fact =
        key_wrap_creation_fact(recipient.id, source.id, signer.id, source_descriptor)
            .expect("create local key wrap creation fact");

    let first = KeyWrapCreationProjector::new()
        .project(
            &creation_fact,
            &creation_context(
                &creation_fact,
                &recipient,
                &source,
                &signer,
                workspace,
                endpoint,
            ),
        )
        .expect("project first key wrap creation");
    let second = KeyWrapCreationProjector::new()
        .project(
            &creation_fact,
            &creation_context(
                &creation_fact,
                &recipient,
                &source,
                &signer,
                workspace,
                endpoint,
            ),
        )
        .expect("project second key wrap creation");

    assert!(first.effects.intents.is_empty());
    assert!(first.effects.local_intents.is_empty());
    assert_eq!(first.effects.facts.len(), 1);
    assert_eq!(first.effects.facts, second.effects.facts);
    let key_wrap_fact = first.effects.facts[0].clone();
    let wrap = key_wrap_layout::decode_key_wrap(&key_wrap_fact.bytes).expect("decode key wrap");
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

    let recovery_fact = key_wrap_recovery_fact(
        workspace,
        frontier,
        recipient.id,
        key_wrap_fact.id,
        local_recipient.id,
        key_wrap_fact.timestamp,
    )
    .expect("create local key wrap recovery fact");
    let recovery = KeyWrapRecoveryProjector::new()
        .project(
            &recovery_fact,
            &recovery_context(
                &recovery_fact,
                &key_wrap_fact,
                &recipient,
                &frontier_fact,
                &local_recipient,
                workspace,
            ),
        )
        .expect("project key wrap recovery");

    assert!(recovery.effects.intents.is_empty());
    assert!(recovery.effects.local_intents.is_empty());
    assert_eq!(recovery.effects.facts.len(), 1);
    assert_eq!(recovery.effects.facts[0].id, source.id);
    assert_eq!(recovery.effects.facts[0].bytes, source.bytes);
}

fn creation_context(
    owner: &Fact,
    recipient: &Fact,
    source: &Fact,
    signer: &Fact,
    workspace_id: [u8; 32],
    endpoint_id: [u8; 32],
) -> ProjectionContext {
    let scope = workspace_scope(workspace_id);
    let recipient_need = ContextNeed::range(
        owner.id,
        "recipient_key",
        scope.clone(),
        recipient.id,
        recipient.id,
    );
    let source_need = ContextNeed::range(
        owner.id,
        "local_secret_source",
        FactScope::Local,
        source.id,
        source.id,
    );
    let signer_need = ContextNeed::range(
        owner.id,
        "local_signer_secret",
        scope,
        endpoint_id,
        endpoint_id,
    );
    ProjectionContext::from_matches(vec![
        matched(recipient_need, recipient.clone()),
        matched(source_need, source.clone()),
        matched(signer_need, signer.clone()),
    ])
}

fn recovery_context(
    owner: &Fact,
    key_wrap: &Fact,
    recipient: &Fact,
    frontier: &Fact,
    local_recipient: &Fact,
    workspace_id: [u8; 32],
) -> ProjectionContext {
    let scope = workspace_scope(workspace_id);
    let key_wrap_need = ContextNeed::range(
        owner.id,
        "sync_key_wrap",
        scope.clone(),
        key_wrap.id,
        key_wrap.id,
    );
    let recipient_need = ContextNeed::range(
        owner.id,
        "recipient_key",
        scope.clone(),
        recipient.id,
        recipient.id,
    );
    let frontier_need = ContextNeed::range(
        owner.id,
        "auth_removal_frontier",
        scope.clone(),
        frontier.id,
        frontier.id,
    );
    let local_recipient_need = ContextNeed::range(
        owner.id,
        "local_recipient_key",
        scope,
        recipient.id,
        recipient.id,
    );
    ProjectionContext::from_matches(vec![
        matched(key_wrap_need, key_wrap.clone()),
        matched(recipient_need, recipient.clone()),
        matched(frontier_need, frontier.clone()),
        matched(local_recipient_need, local_recipient.clone()),
    ])
}

fn matched(need: ContextNeed, payload: Fact) -> MatchedContext {
    MatchedContext {
        offer: ContextOffer::range(
            payload.id,
            need.role.clone(),
            need.scope.clone(),
            need.start_key.as_bytes(),
            need.end_key.as_bytes(),
        ),
        need,
        payload,
    }
}

fn recipient_key_fact(workspace_id: [u8; 32], endpoint_id: [u8; 32], public_key: [u8; 32]) -> Fact {
    let private_key = [9; 32];
    let recipient = RecipientKeyFact {
        workspace_id,
        endpoint_id,
        recipient_key: public_key,
        previous_recipient_key_id: NO_PREVIOUS_RECIPIENT_KEY,
        created_at_ms: 10,
        signer_public_key: crypto::ed25519_public_key(&private_key),
    };
    Fact::new(
        workspace_scope(workspace_id),
        10,
        recipient_key_layout::encode_recipient_key(&recipient).expect("encode recipient"),
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
        local_signer_layout::encode_fact(&LocalSignerSecretFact {
            workspace_id,
            signer_id,
            public_key: crypto::ed25519_public_key(&private_key),
            private_key,
        })
        .expect("encode signer secret"),
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
        10,
        local_recipient_layout::encode_local_recipient_key(&LocalRecipientKeyFact {
            workspace_id,
            recipient_key_id,
            recipient_key,
            recipient_secret,
        })
        .expect("encode local recipient key"),
    )
}

fn removal_frontier_fact(workspace_id: [u8; 32], owner_endpoint_id: [u8; 32]) -> Fact {
    let private_key = [9; 32];
    let frontier = RemovalFrontierFact {
        workspace_id,
        owner_endpoint_id,
        created_at_ms: 20,
        signer_public_key: crypto::ed25519_public_key(&private_key),
    };
    Fact::new(
        workspace_scope(workspace_id),
        20,
        removal_frontier_layout::encode_removal_frontier(&frontier)
            .expect("encode removal frontier"),
    )
}

use topo::core::facts::{Fact, FactScope};
use topo::core::pipeline::{ProjectionContext, Projector};
use topo::protocol::{auth, local_secret_payload, root, sealed_payload};

#[test]
fn root_payload_signature_compose_without_payload_becoming_content() {
    let workspace_id = [1; 32];
    let payload_body = sealed_payload::fact::SealedPayloadFact {
        format: 1,
        algorithm: 1,
        header: sealed_payload::fact::PayloadHeader::new(b"nonce").expect("payload header"),
        ciphertext: sealed_payload::fact::PayloadCiphertext::new(b"ciphertext")
            .expect("payload ciphertext"),
    };
    let payload_fact = Fact::new(
        FactScope::Global,
        10,
        sealed_payload::encode::encode_fact(&payload_body).expect("encode payload"),
    );
    let payload_output = sealed_payload::project::SealedPayloadProjector::new()
        .project(&payload_fact, &ProjectionContext::default())
        .expect("project payload");
    assert_eq!(payload_output.offers.len(), 1);
    assert_eq!(
        payload_output.offers[0].role,
        sealed_payload::project::SEALED_PAYLOAD_ROLE
    );
    assert!(payload_output.effects.row_mutations.is_empty());
    assert!(payload_output.effects.intents.is_empty());

    let root_body = root::fact::RootFact {
        family: 99,
        version: 1,
        created_at_ms: 10,
        refs: vec![
            root::fact::RootRef::new(root::roles::WORKSPACE, 0, workspace_id).unwrap(),
            root::fact::RootRef::new(root::roles::CONTENT, 0, payload_fact.id).unwrap(),
        ],
    };
    let root_fact = Fact::new(
        auth::workspace::scope(workspace_id),
        10,
        root::encode::encode_fact(&root_body).expect("encode root"),
    );
    let root_output = root::project::RootProjector::new()
        .project(&root_fact, &ProjectionContext::default())
        .expect("project root");
    assert!(root_output
        .offers
        .iter()
        .any(|offer| offer.role == root::project::ROOT_ENVELOPE_ROLE));
    let share = topo::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync(
        &root_output.effects.intents[0],
    )
    .expect("decode root sync share");
    assert_eq!(share.owner_fact_id, root_fact.id);
    assert!(share.context_have.contains(&payload_fact.id));

    let signature_fact = auth::signature::author::sign_fact(workspace_id, &root_fact, &[9; 32], 10)
        .expect("sign root");
    let signature_output = auth::signature::project::SignatureProjector::new()
        .project(&signature_fact, &ProjectionContext::default())
        .expect("project signature");
    assert_eq!(signature_output.offers.len(), 1);
    assert_eq!(
        signature_output.offers[0].role,
        auth::signature::project::SIGNATURE_PROOF_ROLE
    );
}

#[test]
fn local_secret_payload_is_local_only_and_opaque() {
    let secret = local_secret_payload::fact::LocalSecretPayloadFact {
        family: 7,
        version: 1,
        bytes: local_secret_payload::fact::LocalSecretBytes::new(b"local secret bytes")
            .expect("secret bytes"),
    };
    let local_fact = Fact::new(
        FactScope::Local,
        10,
        local_secret_payload::encode::encode_fact(&secret).expect("encode local secret"),
    );
    let output = local_secret_payload::project::LocalSecretPayloadProjector::new()
        .project(&local_fact, &ProjectionContext::default())
        .expect("project local secret");
    assert_eq!(output.offers.len(), 1);
    assert_eq!(
        output.offers[0].role,
        local_secret_payload::project::LOCAL_SECRET_PAYLOAD_ROLE
    );
    assert!(output.effects.intents.is_empty());

    let global_fact = Fact::new(
        FactScope::Global,
        10,
        local_secret_payload::encode::encode_fact(&secret).expect("encode local secret"),
    );
    assert!(
        local_secret_payload::project::LocalSecretPayloadProjector::new()
            .project(&global_fact, &ProjectionContext::default())
            .is_err()
    );
}

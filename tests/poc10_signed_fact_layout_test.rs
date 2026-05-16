use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::projection::{ProjectionContext, Projector};
use topo::protocol::facts::encryption::fact::{
    KeyWrapFact, LocalHistoryNodeSecretFact, LocalKeySecretFact, LocalRecipientKeyFact,
    WrappedSecretKind,
};
use topo::protocol::facts::encryption::layout as key_wrap_layout;
use topo::protocol::facts::identity::signed_fact::fact::LocalSignerSecretFact;
use topo::protocol::facts::identity::signed_fact::project::SignedFactProjector;
use topo::protocol::facts::identity::signed_fact::{create, layout};
use topo::protocol::matchers::workspace_scope;

#[test]
fn signed_fact_round_trips_and_verifies_key_wrap_payload() {
    let signer_id = [2; 32];
    let private_key = [9; 32];
    let payload = key_wrap_layout::encode_key_wrap(&key_wrap()).expect("key wrap payload");

    let envelope = create::sign_payload(signer_id, &private_key, payload.clone()).expect("sign");
    let encoded = layout::encode_signed_fact(&envelope).expect("encode signed fact");
    let decoded = layout::decode_signed_fact(&encoded).expect("decode signed fact");

    assert_eq!(encoded.len(), layout::SIGNED_FACT_BYTES);
    assert_eq!(decoded.signer_id, signer_id);
    assert_eq!(
        decoded.signer_public_key,
        crypto::ed25519_public_key(&private_key)
    );
    assert_eq!(decoded.inner_type, key_wrap_layout::TYPE_KEY_WRAP);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn signed_fact_bytes_are_deterministic_and_define_fact_id() {
    let workspace = [1; 32];
    let signer_id = [2; 32];
    let private_key = [9; 32];
    let payload = key_wrap_layout::encode_key_wrap(&key_wrap()).expect("key wrap payload");

    let first = create::sign_payload_bytes(signer_id, &private_key, payload.clone()).expect("sign");
    let second = create::sign_payload_bytes(signer_id, &private_key, payload).expect("sign again");

    assert_eq!(first, second);
    let first_fact = Fact::new(workspace_scope(workspace), 10, first);
    let second_fact = Fact::new(workspace_scope(workspace), 10, second);
    assert_eq!(first_fact.id, second_fact.id);
}

#[test]
fn signed_fact_rejects_tampered_payload_and_signature_context() {
    let signer_id = [2; 32];
    let private_key = [9; 32];
    let payload = key_wrap_layout::encode_key_wrap(&key_wrap()).expect("key wrap payload");
    let mut encoded =
        create::sign_payload_bytes(signer_id, &private_key, payload).expect("signed bytes");

    let payload_start = 66 + 4;
    encoded[payload_start + 12] ^= 1;
    assert!(layout::decode_signed_fact(&encoded).is_err());

    let payload = key_wrap_layout::encode_key_wrap(&key_wrap()).expect("key wrap payload");
    let mut encoded =
        create::sign_payload_bytes(signer_id, &private_key, payload).expect("signed bytes");
    encoded[1] ^= 1;
    assert!(layout::decode_signed_fact(&encoded).is_err());
}

#[test]
fn signed_fact_uses_fixed_payload_slot_with_canonical_padding() {
    let signer_id = [2; 32];
    let private_key = [9; 32];
    let oversized = vec![
        key_wrap_layout::TYPE_KEY_WRAP;
        topo::protocol::facts::identity::signed_fact::SIGNED_FACT_PAYLOAD_BYTES + 1
    ];
    assert!(create::sign_payload_bytes(signer_id, &private_key, oversized).is_err());

    let mut encoded = create::sign_payload_bytes(
        signer_id,
        &private_key,
        key_wrap_layout::encode_key_wrap(&key_wrap()).expect("key wrap payload"),
    )
    .expect("signed bytes");
    encoded[layout::SIGNED_FACT_BYTES - crypto::ED25519_SIGNATURE_BYTES - 1] = 1;
    assert!(layout::decode_signed_fact(&encoded).is_err());
}

#[test]
fn local_signer_secret_round_trips_and_offers_signing_context() {
    let workspace = [1; 32];
    let signer_id = [2; 32];
    let private_key = [9; 32];
    let public_key = crypto::ed25519_public_key(&private_key);
    let bytes = layout::encode_local_signer_secret(&LocalSignerSecretFact {
        workspace_id: workspace,
        signer_id,
        public_key,
        private_key,
    })
    .expect("encode signer secret");
    let fact = Fact::new(FactScope::Local, 10, bytes);
    let decoded = layout::decode_local_signer_secret(&fact.bytes).expect("decode signer secret");

    assert_eq!(decoded.workspace_id, workspace);
    assert_eq!(decoded.signer_id, signer_id);
    assert_eq!(decoded.public_key, public_key);
    let output = SignedFactProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect("project signer secret");
    assert_eq!(output.offers.len(), 1);
    assert_eq!(output.offers[0].owner, fact.id);
    assert_eq!(output.offers[0].payload_ref, fact.id);
    assert_eq!(output.offers[0].scope, workspace_scope(workspace));
}

#[test]
fn local_signer_secret_must_be_local_scope() {
    let workspace = [1; 32];
    let signer_id = [2; 32];
    let private_key = [9; 32];
    let bytes = layout::encode_local_signer_secret(&LocalSignerSecretFact {
        workspace_id: workspace,
        signer_id,
        public_key: crypto::ed25519_public_key(&private_key),
        private_key,
    })
    .expect("encode signer secret");
    let fact = Fact::new(workspace_scope(workspace), 10, bytes);

    let err = SignedFactProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect_err("workspace-scoped local signer is rejected");
    assert!(err.contains("local scope"), "{err}");
}

#[test]
fn signed_fact_rejects_private_payload_tags() {
    let signer_id = [2; 32];
    let private_key = [9; 32];
    let local_signer_payload = layout::encode_local_signer_secret(&LocalSignerSecretFact {
        workspace_id: [1; 32],
        signer_id,
        public_key: crypto::ed25519_public_key(&private_key),
        private_key,
    })
    .expect("encode local signer secret");
    let local_root_payload = key_wrap_layout::encode_local_key_secret(&LocalKeySecretFact {
        workspace_id: [1; 32],
        frontier_id: [3; 32],
        owner_endpoint_id: signer_id,
        created_at_ms: 10,
        key_secret: [4; 32],
    })
    .expect("encode local root");
    let local_history_payload =
        key_wrap_layout::encode_local_history_node_secret(&LocalHistoryNodeSecretFact {
            workspace_id: [1; 32],
            frontier_id: [3; 32],
            owner_endpoint_id: signer_id,
            source_secret_id: [5; 32],
            range_start: 8,
            range_width: 8,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            tombstone_node_id: [7; 32],
            node_secret: [8; 32],
        })
        .expect("encode local history");
    let local_recipient_payload =
        key_wrap_layout::encode_local_recipient_key(&LocalRecipientKeyFact {
            workspace_id: [1; 32],
            recipient_key_id: [3; 32],
            recipient_key: crypto::x25519_public_key(&[4; 32]),
            recipient_secret: [4; 32],
        })
        .expect("encode local recipient");

    for payload in [
        local_signer_payload,
        local_root_payload,
        local_history_payload,
        local_recipient_payload,
    ] {
        assert!(
            create::sign_payload(signer_id, &private_key, payload).is_err(),
            "private local payload must not be signable"
        );
    }
}

fn key_wrap() -> KeyWrapFact {
    KeyWrapFact {
        workspace_id: [1; 32],
        created_at_ms: 10,
        signer_endpoint_id: [2; 32],
        frontier_id: [3; 32],
        wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
        wrapped_secret_id: [4; 32],
        wrapped_source_secret_id: [0; 32],
        wrapped_tombstone_node_id: [0; 32],
        range_start: 0,
        range_width: 0,
        bit_depth: 0,
        fact_id_prefix: [0; 32],
        recipient_key_id: [5; 32],
        sender_wrap_public_key: [6; 32],
        nonce: [7; 24],
        ciphertext: [8; 48],
    }
}

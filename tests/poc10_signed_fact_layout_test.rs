use topo::core::crypto;
use topo::core::facts::Fact;
use topo::event_modules::encryption::context::workspace_scope;
use topo::event_modules::encryption::fact::{KeyWrapFact, WrappedSecretKind};
use topo::event_modules::encryption::layout as key_wrap_layout;
use topo::event_modules::signed_fact::{create, layout};

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
        topo::event_modules::signed_fact::SIGNED_FACT_PAYLOAD_BYTES + 1
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
        event_id_prefix: [0; 32],
        recipient_key_id: [5; 32],
        sender_wrap_public_key: [6; 32],
        nonce: [7; 24],
        ciphertext: [8; 48],
    }
}

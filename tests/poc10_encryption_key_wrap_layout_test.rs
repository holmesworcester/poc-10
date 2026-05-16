use topo::core::crypto::{self, XCHACHA20_POLY1305_NONCE_BYTES};
use topo::protocol::facts::encryption::fact::{
    KeyWrapFact, LocalRecipientKeyFact, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
};
use topo::protocol::facts::encryption::layout::{
    decode_key_wrap, decode_local_recipient_key, encode_key_wrap, encode_local_recipient_key,
    frontier_root_key_wrap_coordinate_key, history_node_key_wrap_coordinate_key,
    key_wrap_coordinate_key, KEY_WRAP_BYTES, KEY_WRAP_COORDINATE_KEY_BYTES,
};

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn root_fact() -> KeyWrapFact {
    KeyWrapFact {
        workspace_id: id(1),
        created_at_ms: 0,
        signer_endpoint_id: id(20),
        frontier_id: id(2),
        wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
        wrapped_secret_id: id(3),
        wrapped_source_secret_id: [0; 32],
        wrapped_tombstone_node_id: [0; 32],
        range_start: 0,
        range_width: 0,
        bit_depth: 0,
        fact_id_prefix: [0; 32],
        recipient_key_id: id(4),
        sender_wrap_public_key: id(5),
        nonce: [6; XCHACHA20_POLY1305_NONCE_BYTES],
        ciphertext: [7; KEY_WRAP_CIPHERTEXT_BYTES],
    }
}

fn history_fact() -> KeyWrapFact {
    let mut prefix = [0; 32];
    prefix[0] = 0b1010_0000;
    KeyWrapFact {
        workspace_id: id(11),
        created_at_ms: 0,
        signer_endpoint_id: id(20),
        frontier_id: id(12),
        wrapped_secret_kind: WrappedSecretKind::HistoryNode,
        wrapped_secret_id: id(13),
        wrapped_source_secret_id: id(14),
        wrapped_tombstone_node_id: id(15),
        range_start: 42,
        range_width: 1,
        bit_depth: 4,
        fact_id_prefix: prefix,
        recipient_key_id: id(16),
        sender_wrap_public_key: id(17),
        nonce: [18; XCHACHA20_POLY1305_NONCE_BYTES],
        ciphertext: [19; KEY_WRAP_CIPHERTEXT_BYTES],
    }
}

#[test]
fn key_wrap_layout_round_trips_fixed_width_root() {
    let fact = root_fact();

    let encoded = encode_key_wrap(&fact).expect("encode key wrap");
    assert_eq!(encoded.len(), KEY_WRAP_BYTES);

    let decoded = decode_key_wrap(&encoded).expect("decode key wrap");
    assert_eq!(decoded, fact);

    let coordinate_key = key_wrap_coordinate_key(&fact).expect("coordinate key");
    assert_eq!(coordinate_key.len(), KEY_WRAP_COORDINATE_KEY_BYTES);
    assert_eq!(
        coordinate_key,
        frontier_root_key_wrap_coordinate_key(
            fact.workspace_id,
            fact.frontier_id,
            fact.recipient_key_id
        )
    );
}

#[test]
fn history_node_coordinate_is_deterministic_and_distinct_from_root() {
    let fact = history_fact();

    let coordinate_key = key_wrap_coordinate_key(&fact).expect("coordinate key");
    let helper_key = history_node_key_wrap_coordinate_key(
        fact.workspace_id,
        fact.frontier_id,
        fact.recipient_key_id,
        fact.range_start,
        fact.range_width,
        fact.bit_depth,
        fact.fact_id_prefix,
    )
    .expect("history coordinate key");
    assert_eq!(coordinate_key, helper_key);

    let root_key = frontier_root_key_wrap_coordinate_key(
        fact.workspace_id,
        fact.frontier_id,
        fact.recipient_key_id,
    );
    assert_ne!(coordinate_key, root_key);

    let mut changed_prefix = fact.fact_id_prefix;
    changed_prefix[0] = 0b1011_0000;
    let changed_key = history_node_key_wrap_coordinate_key(
        fact.workspace_id,
        fact.frontier_id,
        fact.recipient_key_id,
        fact.range_start,
        fact.range_width,
        fact.bit_depth,
        changed_prefix,
    )
    .expect("changed history coordinate key");
    assert_ne!(coordinate_key, changed_key);
}

#[test]
fn root_key_wrap_requires_empty_history_coordinate() {
    let mut fact = root_fact();
    fact.range_width = 1;

    let err = encode_key_wrap(&fact).expect_err("root coordinate must be empty");
    assert!(err.contains("frontier root key wrap target coordinate must be empty"));
}

#[test]
fn history_key_wrap_requires_valid_history_coordinate() {
    let mut fact = history_fact();
    fact.range_width = 3;
    let err = encode_key_wrap(&fact).expect_err("history width must be power of two");
    assert!(err.contains("range_width"));

    let mut fact = history_fact();
    fact.fact_id_prefix[1] = 1;
    let err = encode_key_wrap(&fact).expect_err("history prefix must be masked");
    assert!(err.contains("fact_id_prefix"));
}

#[test]
fn sender_wrap_public_key_and_nonce_are_required_and_round_trip() {
    let mut fact = root_fact();
    fact.sender_wrap_public_key = [0; 32];
    let err = encode_key_wrap(&fact).expect_err("sender wrap public key is required");
    assert!(err.contains("sender_wrap_public_key"));

    let mut fact = root_fact();
    fact.nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
    let err = encode_key_wrap(&fact).expect_err("nonce is required");
    assert!(err.contains("nonce"));

    let fact = root_fact();
    let decoded = decode_key_wrap(&encode_key_wrap(&fact).expect("encode")).expect("decode");
    assert_eq!(decoded.sender_wrap_public_key, fact.sender_wrap_public_key);
    assert_eq!(decoded.nonce, fact.nonce);
}

#[test]
fn local_recipient_key_requires_matching_secret_and_public_key() {
    let secret = [21; 32];
    let fact = LocalRecipientKeyFact {
        workspace_id: id(22),
        recipient_key_id: id(23),
        recipient_key: crypto::x25519_public_key(&secret),
        recipient_secret: secret,
    };

    let encoded = encode_local_recipient_key(&fact).expect("encode local recipient");
    assert_eq!(
        decode_local_recipient_key(&encoded).expect("decode local recipient"),
        fact
    );

    let mut wrong_public = fact.clone();
    wrong_public.recipient_key = id(24);
    let err = encode_local_recipient_key(&wrong_public).expect_err("public must match secret");
    assert!(err.contains("secret does not match public key"));

    let mut empty_secret = fact;
    empty_secret.recipient_secret = [0; 32];
    let err = encode_local_recipient_key(&empty_secret).expect_err("secret is required");
    assert!(err.contains("recipient_secret"));
}

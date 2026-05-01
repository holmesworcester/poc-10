use super::*;

#[test]
fn test_project_key_secret_valid() {
    let conn = setup();
    let recorded_by = "peer1";
    let key_bytes: [u8; 32] = rand::random();
    let (_sk, blob) = make_key_secret(key_bytes);
    let eid = insert_event_raw(&conn, recorded_by, &blob);

    let result = project_one(&conn, recorded_by, &eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Verify in key_secrets table. Plan.md Stage 3.5 step 5C: the
    // legacy `recorded_by` shadow column has been dropped — read
    // by `(workspace_id, event_id)`. The fixture builds key_secret
    // with `workspace_id: [0u8; 32]`.
    let eid_b64 = event_id_to_base64(&eid);
    let workspace_id_b64 = event_id_to_base64(&[0u8; 32]);
    let stored_key: Vec<u8> = conn
        .query_row(
            "SELECT key_bytes FROM key_secrets WHERE event_id = ?1 AND workspace_id = ?2",
            rusqlite::params![&eid_b64, &workspace_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_key, key_bytes.as_slice());
}

#[test]
fn test_encrypted_message_valid() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let key_bytes: [u8; 32] = rand::random();

    // Create and project secret key
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
    let r = project_one(&conn, recorded_by, &sk_eid).unwrap();
    assert_eq!(r, ProjectionDecision::Valid);

    // Create identity chain for signing the inner message
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create signed inner message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "encrypted hello");

    // Encrypt it
    let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Verify inner message is in messages table (using encrypted event_id)
    let enc_b64 = event_id_to_base64(&enc_eid);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&enc_b64, recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn test_encrypted_blocks_on_missing_key() {
    let conn = setup();
    let recorded_by = "peer1";
    let key_bytes: [u8; 32] = rand::random();

    // Pre-compute key event_id without inserting
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = hash_event(&sk_blob);

    // Create identity chain for signing the inner message
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create encrypted event referencing the missing key
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "blocked encrypted");
    let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    match result {
        ProjectionDecision::Block { missing } => {
            assert_eq!(missing.len(), 1);
            assert_eq!(missing[0], sk_eid);
        }
        other => panic!("expected Block, got {:?}", other),
    }
}

#[test]
fn test_encrypted_unblocks_when_key_arrives() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let key_bytes: [u8; 32] = rand::random();

    // Pre-compute key event_id
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = hash_event(&sk_blob);

    // Create identity chain for signing the inner message
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Insert encrypted event first (before key)
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "out of order encrypted");
    let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    // Project → Block
    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));

    // Now insert and project the secret key
    insert_event_raw(&conn, recorded_by, &sk_blob);
    let r = project_one(&conn, recorded_by, &sk_eid).unwrap();
    assert_eq!(r, ProjectionDecision::Valid);

    // Encrypted event should have been cascade-unblocked
    let enc_b64 = event_id_to_base64(&enc_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        valid,
        "encrypted event should be auto-projected after key arrives"
    );

    // Verify inner message was projected
    let msg_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&enc_b64, recorded_by],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(msg_count, 1);
}

#[test]
fn test_encrypted_wrong_key_rejects() {
    let conn = setup();
    let recorded_by = "peer1";
    let key_a: [u8; 32] = rand::random();
    let key_b: [u8; 32] = rand::random();

    // Create and project key B
    let (_sk_b, sk_b_blob) = make_key_secret(key_b);
    let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);
    project_one(&conn, recorded_by, &sk_b_eid).unwrap();

    // Create identity chain for signing the inner message
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Encrypt with key A but reference key B
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "wrong key test");
    let (_enc, enc_blob) = make_encrypted_event(&key_a, &msg_blob, EVENT_TYPE_MESSAGE, &sk_b_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(reason.contains("decryption failed"), "reason: {}", reason);
        }
        other => panic!("expected Reject, got {:?}", other),
    }
}

#[test]
fn test_encrypted_inner_type_mismatch_rejects() {
    use crate::event_modules::reaction::REACTION_WIRE_SIZE;

    let conn = setup();
    let recorded_by = "peer1";
    let key_bytes: [u8; 32] = rand::random();

    // Create and project key
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
    project_one(&conn, recorded_by, &sk_eid).unwrap();

    // Craft a reaction-sized blob whose first byte is MESSAGE type (1)
    // to trigger inner type mismatch at the pipeline level.
    let reaction_wire_size = REACTION_WIRE_SIZE;
    let mut fake_inner = vec![0u8; reaction_wire_size];
    fake_inner[0] = EVENT_TYPE_MESSAGE; // wrong: says message, envelope says reaction

    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key_bytes, &fake_inner).unwrap();
    let enc = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: now_ms(),
        key_event_id: sk_eid,
        inner_type_code: EVENT_TYPE_REACTION, // declares reaction
        nonce,
        ciphertext, // 234 bytes, matches reaction wire size
        auth_tag,
    });
    let enc_blob = events::encode_event(&enc).unwrap();
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            // In fixed-size world, type mismatch manifests as parse error:
            // the 234-byte ciphertext decrypts but can't parse as type 1 (1194 bytes)
            assert!(
                reason.contains("inner type mismatch")
                    || reason.contains("inner event parse error"),
                "reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }
}

#[test]
fn test_encrypted_nested_rejects() {
    use crate::event_modules::layout::common::{ENCRYPTED_AUTH_TAG_BYTES, ENCRYPTED_HEADER_BYTES};

    let conn = setup();
    let recorded_by = "peer1";
    let key_bytes: [u8; 32] = rand::random();

    // Create and project key
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
    project_one(&conn, recorded_by, &sk_eid).unwrap();

    // inner_type_code=5 (encrypted) is now rejected at parser level
    // (encrypted_inner_wire_size returns None). Construct raw blob manually.
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "nested inner");
    let (_inner_enc, inner_enc_blob) =
        make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);

    // Manually build an outer encrypted blob with inner_type_code=5
    let (nonce, raw_ct, auth_tag) = encrypt_event_blob(&key_bytes, &inner_enc_blob).unwrap();
    let total = ENCRYPTED_HEADER_BYTES + raw_ct.len() + ENCRYPTED_AUTH_TAG_BYTES;
    let mut buf = vec![0u8; total];
    buf[0] = EVENT_TYPE_ENCRYPTED;
    buf[1..9].copy_from_slice(&now_ms().to_le_bytes());
    buf[9..41].copy_from_slice(&sk_eid);
    buf[41] = EVENT_TYPE_ENCRYPTED; // inner_type_code = 5 (nested)
    buf[42..54].copy_from_slice(&nonce);
    buf[54..54 + raw_ct.len()].copy_from_slice(&raw_ct);
    buf[54 + raw_ct.len()..].copy_from_slice(&auth_tag);

    let outer_eid = insert_event_raw(&conn, recorded_by, &buf);
    let result = project_one(&conn, recorded_by, &outer_eid).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            // Parser rejects unknown inner_type_code=5 before pipeline even runs
            assert!(reason.contains("parse error"), "reason: {}", reason);
        }
        other => panic!("expected Reject, got {:?}", other),
    }
}

#[test]
fn test_encrypted_inner_dep_blocks() {
    let conn = setup();
    let recorded_by = "peer1";
    let key_bytes: [u8; 32] = rand::random();

    // Create and project key
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
    project_one(&conn, recorded_by, &sk_eid).unwrap();

    // Create identity chain for signing the inner reaction
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create encrypted reaction with missing target
    let fake_target = [88u8; 32];
    let (_rxn, rxn_blob) =
        make_reaction_signed(&signing_key, &signer_eid, &fake_target, "\u{1f44d}");
    let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &rxn_blob, 2, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    match result {
        ProjectionDecision::Block { missing } => {
            assert!(missing.contains(&fake_target));
        }
        other => panic!("expected Block on inner dep, got {:?}", other),
    }

    // Verify NOT in valid_events
    let enc_b64 = event_id_to_base64(&enc_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!valid);
}

#[test]
fn test_encrypted_inner_dep_unblocks() {
    let conn = setup();
    let recorded_by = "peer1";
    let _net_eid = setup_workspace_event(&conn, recorded_by);
    let key_bytes: [u8; 32] = rand::random();

    // Create and project key
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
    project_one(&conn, recorded_by, &sk_eid).unwrap();

    // Create identity chain for signing inner events
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Create target message (pre-compute but don't insert yet)
    let (_msg, msg_blob) =
        make_message_signed(&signing_key, &signer_eid, "target for encrypted rxn");
    let msg_eid = canonical_test_event_id(&conn, recorded_by, &msg_blob);

    // Create encrypted reaction targeting the message
    let (_rxn, rxn_blob) =
        make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{2764}\u{fe0f}");
    let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &rxn_blob, 2, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    // Project → Block on inner dep (message)
    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Block { .. }));

    // Now insert and project the message
    let inserted_msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    assert_eq!(inserted_msg_eid, msg_eid);
    let r = project_one(&conn, recorded_by, &msg_eid).unwrap();
    assert_eq!(r, ProjectionDecision::Valid);

    // Encrypted reaction should have been cascade-unblocked
    let enc_b64 = event_id_to_base64(&enc_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        valid,
        "encrypted reaction should be auto-projected after target message arrives"
    );
}

#[test]
fn test_encrypted_rejection_recorded_durably() {
    let conn = setup();
    let recorded_by = "peer1";
    let key_a: [u8; 32] = rand::random();
    let key_b: [u8; 32] = rand::random();

    // Create and project key B
    let (_sk_b, sk_b_blob) = make_key_secret(key_b);
    let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);
    project_one(&conn, recorded_by, &sk_b_eid).unwrap();

    // Create identity chain for signing the inner message
    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

    // Encrypt with key A, reference key B → decryption fails
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "will be rejected");
    let (_enc, enc_blob) = make_encrypted_event(&key_a, &msg_blob, EVENT_TYPE_MESSAGE, &sk_b_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    assert!(matches!(result, ProjectionDecision::Reject { .. }));

    // Verify in rejected_events
    let enc_b64 = event_id_to_base64(&enc_eid);
    let reason: String = conn
        .query_row(
            "SELECT reason FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(reason.contains("decryption failed"));
}

#[test]
fn test_encrypted_cross_tenant_isolation() {
    let conn = setup();
    let tenant_a = "tenant_a";
    let tenant_b = "tenant_b";
    let _net_eid_a = setup_workspace_event(&conn, tenant_a);
    let key_bytes: [u8; 32] = rand::random();

    // Create and project key for tenant_a only
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = insert_event_raw(&conn, tenant_a, &sk_blob);
    let r = project_one(&conn, tenant_a, &sk_eid).unwrap();
    assert_eq!(r, ProjectionDecision::Valid);

    // Create identity chain for signing the inner message (for tenant_a)
    let (signer_eid, signing_key) = make_identity_chain(&conn, tenant_a);

    // Create encrypted message referencing that key
    let (_msg, msg_blob) =
        make_message_signed(&signing_key, &signer_eid, "tenant-scoped encryption");
    let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
    let enc_eid = insert_event_raw(&conn, tenant_a, &enc_blob);

    // Project for tenant_a → Valid
    let r_a = project_one(&conn, tenant_a, &enc_eid).unwrap();
    assert_eq!(r_a, ProjectionDecision::Valid);

    // Record for tenant_b (also record the sk_blob event)
    insert_recorded_event(&conn, tenant_b, &enc_eid, now_ms() as i64, "test").unwrap();
    insert_recorded_event(&conn, tenant_b, &sk_eid, now_ms() as i64, "test").unwrap();

    // Project encrypted event for tenant_b → Block (key not valid for B)
    let r_b = project_one(&conn, tenant_b, &enc_eid).unwrap();
    match r_b {
        ProjectionDecision::Block { missing } => {
            assert_eq!(missing.len(), 1);
            assert_eq!(missing[0], sk_eid);
        }
        other => panic!("expected Block for tenant_b, got {:?}", other),
    }
}

// ===== Encrypted-inner parity characterization tests (Phase 1) =====
//
// These tests lock the behavioral equivalence boundaries between direct
// event projection and encrypted-inner projection. They must remain green
// through the refactor (Phases 2-3) to prove no semantic drift.

/// Helper: set up a shared encryption context (identity chain + secret key).
/// Returns (signer_eid, signing_key, key_bytes, sk_eid).
fn setup_encryption_ctx(
    conn: &Connection,
    recorded_by: &str,
) -> (EventId, SigningKey, [u8; 32], EventId) {
    let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
    let key_bytes: [u8; 32] = rand::random();
    let (_sk, sk_blob) = make_key_secret(key_bytes);
    let sk_eid = insert_event_raw(conn, recorded_by, &sk_blob);
    let r = project_one(conn, recorded_by, &sk_eid).unwrap();
    assert_eq!(r, ProjectionDecision::Valid);
    (signer_eid, signing_key, key_bytes, sk_eid)
}

// --- Message parity ---

#[test]
fn test_encrypted_parity_message_projected_state() {
    // Verify that an encrypted message produces the same projected row
    // (in `messages`) as a directly projected message, using the
    // *outer* encrypted event_id as the message_id.
    let conn = setup();
    let recorded_by = "peer1";
    let _ws = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key, key_bytes, sk_eid) = setup_encryption_ctx(&conn, recorded_by);

    // Direct message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "direct hello");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    let r_direct = project_one(&conn, recorded_by, &msg_eid).unwrap();
    assert_eq!(r_direct, ProjectionDecision::Valid);

    // Encrypted message with same content
    let (_msg2, msg2_blob) = make_message_signed(&signing_key, &signer_eid, "encrypted hello");
    let (_enc, enc_blob) =
        make_encrypted_event(&key_bytes, &msg2_blob, EVENT_TYPE_MESSAGE, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
    let r_enc = project_one(&conn, recorded_by, &enc_eid).unwrap();
    assert_eq!(r_enc, ProjectionDecision::Valid);

    // Both should be in messages table
    let msg_b64 = event_id_to_base64(&msg_eid);
    let enc_b64 = event_id_to_base64(&enc_eid);

    let direct_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        direct_count, 1,
        "direct message should be in messages table"
    );

    let enc_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        enc_count, 1,
        "encrypted message should be in messages table with outer event_id"
    );

    // Both in valid_events
    let direct_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(direct_valid);

    let enc_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(enc_valid);
}

// --- Reaction parity ---

#[test]
fn test_encrypted_parity_reaction_projected_state() {
    // Verify encrypted reaction produces the same projected row (in `reactions`)
    // as a direct reaction, anchored to outer encrypted event_id.
    let conn = setup();
    let recorded_by = "peer1";
    let _ws = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key, key_bytes, sk_eid) = setup_encryption_ctx(&conn, recorded_by);

    // Create a target message
    let (_msg, msg_blob) = make_message_signed(&signing_key, &signer_eid, "reaction target");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Direct reaction
    let (_rxn, rxn_blob) = make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{1f44d}");
    let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
    let r_direct = project_one(&conn, recorded_by, &rxn_eid).unwrap();
    assert_eq!(r_direct, ProjectionDecision::Valid);

    // Encrypted reaction
    let (_rxn2, rxn2_blob) =
        make_reaction_signed(&signing_key, &signer_eid, &msg_eid, "\u{2764}\u{fe0f}");
    let (_enc, enc_blob) =
        make_encrypted_event(&key_bytes, &rxn2_blob, EVENT_TYPE_REACTION, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
    let r_enc = project_one(&conn, recorded_by, &enc_eid).unwrap();
    assert_eq!(r_enc, ProjectionDecision::Valid);

    // Both should be in reactions table
    let rxn_b64 = event_id_to_base64(&rxn_eid);
    let enc_b64 = event_id_to_base64(&enc_eid);

    let direct_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        direct_count, 1,
        "direct reaction should be in reactions table"
    );

    let enc_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        enc_count, 1,
        "encrypted reaction should be in reactions table with outer event_id"
    );
}

// --- Message deletion parity ---

#[test]
fn test_encrypted_parity_deletion_valid() {
    // Verify encrypted message deletion produces the same tombstone state
    // as direct deletion, with the encrypted wrapper event_id in valid_events.
    let conn = setup();
    let recorded_by = "peer1";
    let _ws = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key, key_bytes, sk_eid) = setup_encryption_ctx(&conn, recorded_by);

    // Create and project a message (will be deleted by encrypted deletion)
    let (_msg, msg_blob) =
        make_message_signed(&signing_key, &signer_eid, "to be deleted via encrypted");
    let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
    project_one(&conn, recorded_by, &msg_eid).unwrap();

    // Create deletion event (author_id = [2;32] matches message author)
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &msg_eid, [2u8; 32]);

    // Encrypt the deletion
    let (_enc, enc_blob) =
        make_encrypted_event(&key_bytes, &del_blob, EVENT_TYPE_MESSAGE_DELETION, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
    assert_eq!(result, ProjectionDecision::Valid);

    // Message should be deleted
    let msg_b64 = event_id_to_base64(&msg_eid);
    let msg_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(msg_count, 0, "message should be deleted");

    // Tombstone should exist
    let tomb_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &msg_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tomb_count, 1, "tombstone should exist");

    // Encrypted wrapper event should be in valid_events (outer event anchoring)
    let enc_b64 = event_id_to_base64(&enc_eid);
    let enc_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(enc_valid, "encrypted wrapper should be in valid_events");
}

#[test]
fn test_encrypted_parity_deletion_intent_only() {
    // Encrypted deletion where the target message doesn't exist yet.
    // Should write deletion_intent via inner deletion projector and return Valid.
    let conn = setup();
    let recorded_by = "peer1";
    let _ws = setup_workspace_event(&conn, recorded_by);
    let (signer_eid, signing_key, key_bytes, sk_eid) = setup_encryption_ctx(&conn, recorded_by);

    // Create deletion targeting a non-existent message
    let fake_target = [77u8; 32];
    let (_del, del_blob) = make_deletion_signed(&signing_key, &signer_eid, &fake_target, [2u8; 32]);
    let (_enc, enc_blob) =
        make_encrypted_event(&key_bytes, &del_blob, EVENT_TYPE_MESSAGE_DELETION, &sk_eid);
    let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);
    let result = project_one(&conn, recorded_by, &enc_eid).unwrap();

    // Deletion writes intent and succeeds (no dep-block on target)
    assert_eq!(result, ProjectionDecision::Valid);

    // Verify deletion_intent was written
    let target_b64 = event_id_to_base64(&fake_target);
    let intent_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM deletion_intents WHERE recorded_by = ?1 AND target_kind = 'message' AND target_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(
        intent_count, 1,
        "deletion_intent must be written through encrypted layer"
    );

    // Outer event should be valid
    let enc_b64 = event_id_to_base64(&enc_eid);
    let valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert!(valid, "outer encrypted event should be in valid_events");
}


// Wave 1: file_slice parity tests dropped along with the file/file_slice modules.

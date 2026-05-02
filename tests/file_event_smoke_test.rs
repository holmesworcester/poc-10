//! Smoke tests for the chain-friendly `file` and `file_slice` event modules
//! (Wave 1 ports — see `event_modules/file/` and `event_modules/file_slice/`).
//!
//! Modules covered:
//! - file        (type 45) — descriptor + bao outboard projector
//! - file_slice  (type 46) — per-slice integrity check (blake3) projector
//! - bao_verify  — per-slice verification against the file's outboard
//!
//! All four tests in the task spec:
//!  1. file_event_round_trip_and_project
//!  2. file_slice_event_round_trip_and_project
//!  3. file_slice_verifies_against_file_outboard
//!  4. file_slice_with_invalid_hash_rejects

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use topo::crypto::bao_verify;
use topo::event_modules::connection::local_signing_key;
use topo::event_modules::{
    encode_event, file::FileEvent, file_slice::FileSliceEvent, ParsedEvent,
};
use topo::runtime::control_loop::work_item::{BlakeId, EndpointId};
use topo::runtime::control_loop::{
    handle_inbound_bytes, InboundOrigin, InboundOutcome, InnerEventDisposition,
};
use topo::event_modules::connection::wrap::{wrap_bootstrap, InnerCanonicalEvent};
use topo::state::db::control_loop_tables::ensure_schema as ensure_substrate_schema;
use topo::state::events_canonical::{upsert_event, EventRow, EventScope, EventStatus};

fn sender_sk() -> SigningKey {
    SigningKey::from_bytes(&[0x11u8; 32])
}
fn recipient_sk() -> SigningKey {
    SigningKey::from_bytes(&[0x22u8; 32])
}
fn sender_eid() -> EndpointId {
    sender_sk().verifying_key().to_bytes()
}
fn recipient_eid() -> EndpointId {
    recipient_sk().verifying_key().to_bytes()
}

const TEST_WORKSPACE_ID: [u8; 32] = [0x77u8; 32];
const TEST_SIGNER_ID: [u8; 32] = [0x88u8; 32];

fn open_db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    ensure_substrate_schema(&c).unwrap();
    // Registry-driven module schema bring-up.
    topo::event_modules::ensure_all_module_schemas(&c).unwrap();
    let path = c.path().unwrap_or("").to_string();
    local_signing_key::install_for_path(&path, recipient_sk());
    c
}

fn origin() -> InboundOrigin {
    InboundOrigin {
        remote_endpoint_id: Some(sender_eid()),
        ip: Some("127.0.0.1".to_string()),
        port: Some(4242),
    }
}

fn wrap_one_with_ws(blob: Vec<u8>, ws: [u8; 32]) -> Vec<u8> {
    let inner = vec![InnerCanonicalEvent {
        workspace_id: ws,
        bytes: blob,
    }];
    let frame = wrap_bootstrap(&sender_sk(), recipient_eid(), &inner).unwrap();
    frame.as_bytes().to_vec()
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

fn b64(id: [u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(id)
}

/// Pre-seed the signer's `signed_by` dep so the chain doesn't block on it.
fn seed_signer(db: &Connection, signer_id: BlakeId, ws: [u8; 32]) {
    upsert_event(
        db,
        &EventRow {
            event_id: signer_id,
            canonical_event_bytes: vec![1, 2, 3],
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// 1. file event round-trip + project
// ---------------------------------------------------------------------------

#[test]
fn file_event_round_trip_and_project() {
    let c = open_db();
    seed_signer(&c, TEST_SIGNER_ID, TEST_WORKSPACE_ID);

    // Build a file with a real bao outboard derived from 4 KiB of plaintext.
    let plaintext: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let (root_hash, outboard) = bao_verify::compute_outboard(&plaintext).unwrap();

    let f = FileEvent {
        created_at_ms: 1_000,
        workspace_id: TEST_WORKSPACE_ID,
        content_hash: root_hash,
        size_bytes: plaintext.len() as u64,
        slice_count: 4,
        signed_by: TEST_SIGNER_ID,
        signer_type: 5,
        signature: [0u8; 64],
        file_name: "smoke.bin".to_string(),
        bao_outboard: outboard,
    };
    let blob = encode_event(&ParsedEvent::File(f.clone())).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, TEST_WORKSPACE_ID);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, inner_id);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "file event must apply directly under the new chain"
    );

    // Projection row exists keyed by `(workspace_id, event_id)`.
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM files
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![b64(TEST_WORKSPACE_ID), b64(inner_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1, "files row must exist keyed by (workspace_id, event_id)");

    // Content was preserved.
    let (file_name, size_bytes, slice_count, content_hash, bao_outboard_len): (
        String,
        i64,
        i64,
        Vec<u8>,
        i64,
    ) = c
        .query_row(
            "SELECT file_name, size_bytes, slice_count, content_hash, length(bao_outboard)
             FROM files WHERE event_id = ?1",
            params![b64(inner_id)],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(file_name, "smoke.bin");
    assert_eq!(size_bytes, 4096);
    assert_eq!(slice_count, 4);
    assert_eq!(content_hash.as_slice(), &root_hash[..]);
    assert!(bao_outboard_len > 0, "bao_outboard should have been stored");
}

// ---------------------------------------------------------------------------
// 2. file_slice event round-trip + project (self-validating: hash check)
// ---------------------------------------------------------------------------

#[test]
fn file_slice_event_round_trip_and_project() {
    let c = open_db();
    seed_signer(&c, TEST_SIGNER_ID, TEST_WORKSPACE_ID);

    // Pre-seed the file_event_id dep so the chain doesn't block it.
    let file_event_id_bytes: [u8; 32] = [0xCC; 32];
    upsert_event(
        &c,
        &EventRow {
            event_id: file_event_id_bytes,
            canonical_event_bytes: vec![9, 9, 9],
            workspace_id: Some(TEST_WORKSPACE_ID),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let payload = vec![0xAB; 1024];
    let slice_hash_bytes: [u8; 32] = *blake3::hash(&payload).as_bytes();

    let s = FileSliceEvent {
        created_at_ms: 2_000,
        workspace_id: TEST_WORKSPACE_ID,
        file_event_id: file_event_id_bytes,
        slice_index: 0,
        slice_hash: slice_hash_bytes,
        signed_by: TEST_SIGNER_ID,
        signer_type: 5,
        signature: [0u8; 64],
        slice_bytes: payload.clone(),
    };
    let blob = encode_event(&ParsedEvent::FileSlice(s.clone())).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, TEST_WORKSPACE_ID);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, inner_id);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "file_slice event must apply (self-validating hash)"
    );

    // Projection row keyed by (workspace_id, event_id), unique across slot.
    let (slice_index, file_event_id_b64, hash_blob, bytes_len): (i64, String, Vec<u8>, i64) = c
        .query_row(
            "SELECT slice_index, file_event_id, slice_hash, length(slice_bytes)
             FROM file_slices
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![b64(TEST_WORKSPACE_ID), b64(inner_id)],
            |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            },
        )
        .unwrap();
    assert_eq!(slice_index, 0);
    assert_eq!(file_event_id_b64, b64(file_event_id_bytes));
    assert_eq!(hash_blob.as_slice(), &slice_hash_bytes[..]);
    assert_eq!(bytes_len, 1024);
}

// ---------------------------------------------------------------------------
// 3. file_slice verifies against file outboard (bao end-to-end)
// ---------------------------------------------------------------------------

#[test]
fn file_slice_verifies_against_file_outboard() {
    // The whole-file integrity proof: build a 4 KiB file with bao, derive
    // a slice proof for each chunk, project each slice via the chain, then
    // verify the assembled output (per slice via bao_verify::verify_slice)
    // matches the original plaintext under the file's content_hash.

    let c = open_db();
    seed_signer(&c, TEST_SIGNER_ID, TEST_WORKSPACE_ID);

    let plaintext: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let (root_hash, outboard) = bao_verify::compute_outboard(&plaintext).unwrap();

    // Slice config: 1 KiB plaintext per slice → 4 slices.
    let slice_size: u64 = 1024;
    let total_slices = ((plaintext.len() as u64 + slice_size - 1) / slice_size) as u32;

    // 1. Project the file event.
    let file_ev = FileEvent {
        created_at_ms: 1_000,
        workspace_id: TEST_WORKSPACE_ID,
        content_hash: root_hash,
        size_bytes: plaintext.len() as u64,
        slice_count: total_slices,
        signed_by: TEST_SIGNER_ID,
        signer_type: 5,
        signature: [0u8; 64],
        file_name: "verify.bin".to_string(),
        bao_outboard: outboard.clone(),
    };
    let file_blob = encode_event(&ParsedEvent::File(file_ev)).unwrap();
    let file_event_id = blake3_id(&file_blob);
    let file_frame = wrap_one_with_ws(file_blob, TEST_WORKSPACE_ID);
    let file_outcome = handle_inbound_bytes(&file_frame, origin(), &c, 1).unwrap();
    matches!(file_outcome, InboundOutcome::InnerEventsProcessed { .. });

    // 2. Project each slice and assert (a) projection succeeds and
    //    (b) we can verify the slice against the file's bao outboard.
    for i in 0..total_slices {
        let slice_start = (i as u64) * slice_size;
        let slice_len = slice_size.min(plaintext.len() as u64 - slice_start);
        let slice_plaintext =
            &plaintext[slice_start as usize..(slice_start + slice_len) as usize];
        let slice_hash: [u8; 32] = *blake3::hash(slice_plaintext).as_bytes();

        // Seed the signer dep again is unnecessary (already applied).
        let s = FileSliceEvent {
            created_at_ms: 2_000 + i as u64,
            workspace_id: TEST_WORKSPACE_ID,
            file_event_id,
            slice_index: i,
            slice_hash,
            signed_by: TEST_SIGNER_ID,
            signer_type: 5,
            signature: [0u8; 64],
            slice_bytes: slice_plaintext.to_vec(),
        };
        let s_blob = encode_event(&ParsedEvent::FileSlice(s)).unwrap();
        let s_frame = wrap_one_with_ws(s_blob, TEST_WORKSPACE_ID);
        let s_outcome =
            handle_inbound_bytes(&s_frame, origin(), &c, 10 + i as i64).unwrap();
        let s_results = match s_outcome {
            InboundOutcome::InnerEventsProcessed { results, .. } => results,
            other => panic!("slice {} unexpected outcome {:?}", i, other),
        };
        assert_eq!(s_results[0].disposition, InnerEventDisposition::Applied);

        // Now extract a per-slice bao proof from the file's outboard
        // and verify. This is the "slice verifies via bao when projected"
        // assertion.
        let proof =
            bao_verify::extract_slice_proof(&plaintext, &outboard, slice_start, slice_len)
                .unwrap();
        let verified =
            bao_verify::verify_slice(&root_hash, &proof, slice_start, slice_len).unwrap();
        assert_eq!(verified, slice_plaintext, "bao verify mismatch for slice {}", i);
    }

    // All four slices in the projection table.
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM file_slices
             WHERE workspace_id = ?1 AND file_event_id = ?2",
            params![b64(TEST_WORKSPACE_ID), b64(file_event_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, total_slices as i64);
}

// ---------------------------------------------------------------------------
// 4. file_slice with invalid hash rejects
// ---------------------------------------------------------------------------

#[test]
fn file_slice_with_invalid_hash_rejects() {
    let c = open_db();
    seed_signer(&c, TEST_SIGNER_ID, TEST_WORKSPACE_ID);

    let payload = vec![0xCD; 256];
    // Tampered: declared hash does NOT match blake3(payload).
    let bogus_hash: [u8; 32] = [0xFFu8; 32];
    let real_hash: [u8; 32] = *blake3::hash(&payload).as_bytes();
    assert_ne!(bogus_hash, real_hash, "test would otherwise be vacuous");

    let s = FileSliceEvent {
        created_at_ms: 3_000,
        workspace_id: TEST_WORKSPACE_ID,
        file_event_id: [0xEE; 32],
        slice_index: 0,
        slice_hash: bogus_hash,
        signed_by: TEST_SIGNER_ID,
        signer_type: 5,
        signature: [0u8; 64],
        slice_bytes: payload,
    };
    // Pre-seed the file_event_id dep so the chain doesn't block on it.
    upsert_event(
        &c,
        &EventRow {
            event_id: [0xEE; 32],
            canonical_event_bytes: vec![9, 9, 9],
            workspace_id: Some(TEST_WORKSPACE_ID),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let blob = encode_event(&ParsedEvent::FileSlice(s)).unwrap();
    let frame = wrap_one_with_ws(blob, TEST_WORKSPACE_ID);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    match &results[0].disposition {
        InnerEventDisposition::Rejected { .. } => {}
        other => panic!("expected Rejected for tampered slice, got {:?}", other),
    }

    // No row should be in file_slices.
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM file_slices", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "rejected slice must not produce a projection row");
}

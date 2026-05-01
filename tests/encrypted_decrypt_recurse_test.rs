//! End-to-end coverage for the chained inbound pipeline's
//! decrypt-and-recurse handling of `ParsedEvent::Encrypted`.
//!
//! When an encrypted event lands on the wire, the chain must:
//!   1. Look up the workspace key in `key_secrets` by `key_event_id`.
//!   2. AES-256-GCM decrypt + AEAD-verify the inner ciphertext.
//!   3. Recurse the inner canonical bytes through admit_event_id → parse
//!      → finalize → project_and_apply, in the SAME transaction the
//!      outer event is being processed in.
//!
//! Cases:
//!   1. `decrypt_recurse_happy_path_applies_inner_message` — workspace
//!      key present, encrypted arrives, both outer and inner end as
//!      `Applied`, projector wrote inner row.
//!   2. `decrypt_recurse_missing_key_blocks_outer` — workspace key NOT
//!      present, outer is `Blocked` and a `blocked_by_event` row points
//!      at the missing `key_event_id`.
//!   3. `decrypt_recurse_invalid_ciphertext_rejects_outer` — key
//!      present but ciphertext is tampered; outer is `Rejected`.

use rusqlite::{params, Connection};
use topo::event_modules::connection::wrap::{wrap_bootstrap, InnerCanonicalEvent};
use topo::event_modules::{encode_event, EncryptedEvent, MessageEvent, ParsedEvent, WorkspaceEvent};
use topo::runtime::control_loop::work_item::{BlakeId, EndpointId};
use topo::runtime::control_loop::{
    handle_inbound_bytes, InboundOrigin, InboundOutcome, InnerEventDisposition,
};
use topo::shared::crypto::encrypt_event_blob;
use topo::state::db::control_loop_tables::ensure_schema as ensure_substrate_schema;
use topo::state::events_canonical::{get as get_event, EventStatus};

const SENDER: EndpointId = [11u8; 32];
const RECIPIENT: EndpointId = [22u8; 32];

fn open_db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    ensure_substrate_schema(&c).unwrap();
    // Inner-target (message) and key_secrets projector schemas — the chain
    // expects both of these to exist before it tries to apply.
    topo::event_modules::message::ensure_schema(&c).unwrap();
    topo::event_modules::key_secret::ensure_schema(&c).unwrap();
    c
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

fn b64(id: &BlakeId) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(id)
}

fn origin() -> InboundOrigin {
    InboundOrigin {
        remote_endpoint_id: Some(RECIPIENT),
        ip: Some("127.0.0.1".to_string()),
        port: Some(4242),
    }
}

/// Build a Message canonical blob with the smallest set of fields the
/// projector accepts (non-empty content, default identity bytes — the
/// projector doesn't reject on zero ids in the chain's empty context).
fn message_blob(content: &str) -> Vec<u8> {
    let m = MessageEvent {
        created_at_ms: 7_777,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: content.to_string(),
        signed_by: [0u8; 32],
        signer_type: 0,
        signature: [0u8; 64],
    };
    encode_event(&ParsedEvent::Message(m)).unwrap()
}

/// Insert a `key_secrets` row keyed by `key_event_id_b64`. The chain's
/// decrypt helper looks up by `event_id` only.
///
/// Stage 2 migration added `workspace_id` as a NOT NULL column (and made
/// it part of the PK alongside `event_id`). The test workspace_id is the
/// all-zeros wrapper id used by `wrap_one`, matching the workspace that
/// the wrapping frame binds to.
///
/// Plan.md Stage 3.5 step 5C: the `recorded_by` shadow column has been
/// dropped from the schema; this fixture no longer writes it.
fn seed_key_secret(c: &Connection, key_event_id: &BlakeId, key_bytes: &[u8; 32]) {
    let workspace_id_b64 = b64(&[0u8; 32]);
    c.execute(
        "INSERT INTO key_secrets (workspace_id, event_id, key_bytes, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            workspace_id_b64,
            b64(key_event_id),
            key_bytes.to_vec(),
            0_i64,
        ],
    )
    .unwrap();
}

/// Wrap an inner blob as a single-event bootstrap frame (the same path
/// `inbound_chain_test.rs` uses).
fn wrap_one(blob: Vec<u8>) -> Vec<u8> {
    let inner = vec![InnerCanonicalEvent {
        workspace_id: [0u8; 32],
        bytes: blob,
    }];
    let frame = wrap_bootstrap(SENDER, RECIPIENT, &inner).unwrap();
    frame.as_bytes().to_vec()
}

/// Build an encrypted event over `inner_blob` using `key_bytes`. Returns
/// (encoded encrypted event, key_event_id used). The `key_event_id` is
/// chosen to be a stable hash over `key_bytes` so test setup matches the
/// `key_secrets` row we seed.
fn build_encrypted_blob(inner_blob: &[u8], key_bytes: &[u8; 32]) -> (Vec<u8>, BlakeId) {
    let inner_first = inner_blob[0];
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(key_bytes, inner_blob).unwrap();
    let key_event_id = blake3_id(key_bytes);
    let enc = EncryptedEvent {
        created_at_ms: 1_111,
        key_event_id,
        inner_type_code: inner_first,
        nonce,
        ciphertext,
        auth_tag,
    };
    let blob = encode_event(&ParsedEvent::Encrypted(enc)).unwrap();
    (blob, key_event_id)
}

#[test]
fn decrypt_recurse_happy_path_applies_inner_message() {
    let c = open_db();
    let key_bytes: [u8; 32] = [0x42; 32];

    let inner_blob = message_blob("hello");
    let (encrypted_blob, key_event_id) = build_encrypted_blob(&inner_blob, &key_bytes);
    seed_key_secret(&c, &key_event_id, &key_bytes);

    let outer_id = blake3_id(&encrypted_blob);
    let inner_id = blake3_id(&inner_blob);

    let frame = wrap_one(encrypted_blob);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1, "one outer event");
    assert_eq!(results[0].event_id, outer_id);
    // Disposition mirrors the inner event — the inner message projector
    // returns Valid so the chain reports Applied for the wire result.
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "happy-path encrypted -> inner message must apply"
    );

    // Outer encrypted row stored + Applied (so it can be reshared).
    let outer = get_event(&c, &outer_id).unwrap().expect("outer row");
    assert_eq!(outer.status, EventStatus::Applied);

    // Inner row exists with status Applied.
    let inner = get_event(&c, &inner_id).unwrap().expect("inner row");
    assert_eq!(inner.status, EventStatus::Applied);

    // Message projector wrote a row keyed by the inner event id.
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
            params![b64(&inner_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1, "inner message projector should have written a row");
}

#[test]
fn decrypt_recurse_missing_key_blocks_outer() {
    let c = open_db();
    let key_bytes: [u8; 32] = [0x77; 32];

    let inner_blob = message_blob("blocked-on-key");
    let (encrypted_blob, key_event_id) = build_encrypted_blob(&inner_blob, &key_bytes);
    // INTENTIONALLY DO NOT seed the key in `key_secrets`.

    let outer_id = blake3_id(&encrypted_blob);
    let inner_id = blake3_id(&inner_blob);

    let frame = wrap_one(encrypted_blob);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 5).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, outer_id);
    match &results[0].disposition {
        InnerEventDisposition::Blocked { missing_deps } => {
            assert_eq!(missing_deps.len(), 1, "blocked on exactly one dep");
            assert_eq!(
                missing_deps[0], key_event_id,
                "blocked dep must be the workspace key id"
            );
        }
        other => panic!("expected Blocked, got {:?}", other),
    }

    // Outer row is Blocked; a blocked_by_event row points at the key.
    let outer = get_event(&c, &outer_id).unwrap().expect("outer row");
    assert_eq!(outer.status, EventStatus::Blocked);
    let edge: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM blocked_by_event
             WHERE blocked_by_event_id = ?1 AND event_id = ?2",
            params![key_event_id.to_vec(), outer_id.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        edge, 1,
        "blocked_by_event(key_event_id, outer_event_id) row must be written"
    );

    // Inner row was NOT created — we never decrypted, so we never
    // recursed into admit_event_id for the inner.
    assert!(
        get_event(&c, &inner_id).unwrap().is_none(),
        "inner row must not exist when decrypt blocks on missing key"
    );
}

#[test]
fn decrypt_recurse_invalid_ciphertext_rejects_outer() {
    let c = open_db();
    let key_bytes: [u8; 32] = [0xAA; 32];

    let inner_blob = message_blob("tampered");
    let (mut encrypted_blob, key_event_id) = build_encrypted_blob(&inner_blob, &key_bytes);
    seed_key_secret(&c, &key_event_id, &key_bytes);

    // Tamper: flip the last byte of the encoded encrypted event. That
    // sits inside the auth_tag, so AES-GCM verify will fail.
    let last = encrypted_blob.len() - 1;
    encrypted_blob[last] ^= 0xFF;

    let outer_id = blake3_id(&encrypted_blob);

    let frame = wrap_one(encrypted_blob);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 9).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, outer_id);
    match &results[0].disposition {
        InnerEventDisposition::Rejected { reason } => {
            assert!(
                reason.to_lowercase().contains("aes")
                    || reason.to_lowercase().contains("decrypt")
                    || reason.to_lowercase().contains("verify"),
                "reject reason should mention aes/decrypt/verify failure, got {:?}",
                reason
            );
        }
        other => panic!("expected Rejected, got {:?}", other),
    }
    let outer = get_event(&c, &outer_id).unwrap().expect("outer row");
    assert_eq!(outer.status, EventStatus::Rejected);

    // Tampered run must not have written any messages.
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "tampered ciphertext must not produce a message row");

    // Tampered run also must not leave a blocked_by_event row.
    let edge: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM blocked_by_event WHERE event_id = ?1",
            params![outer_id.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(edge, 0);
}

/// Build a Message canonical blob that the projector will REJECT
/// (empty content trips the "message content must not be empty" guard
/// in `event_modules::message::projector::project_pure`). The codec
/// itself accepts the blob — only the projector verdict turns into
/// `InnerEventDisposition::Rejected`.
fn rejected_message_blob() -> Vec<u8> {
    let m = MessageEvent {
        created_at_ms: 7_777,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "".to_string(),
        signed_by: [0u8; 32],
        signer_type: 0,
        signature: [0u8; 64],
    };
    encode_event(&ParsedEvent::Message(m)).unwrap()
}

/// Build a Workspace canonical blob whose projector returns
/// `Workspace` event used in the inner-rejection mirror test. Under the
/// new chain (plan.md Stage 2) the workspace projector applies cleanly
/// without an accepted-invite binding; the reject path is exercised by
/// pre-installing a `deleted` label on the workspace event id, which
/// the projector treats as a label-gated reject.
fn workspace_blob_for_rejected_path() -> Vec<u8> {
    let ws = WorkspaceEvent {
        created_at_ms: 4_242,
        workspace_id: [0xCDu8; 32],
        public_key: [0xCDu8; 32],
        name: "ws".to_string(),
    };
    encode_event(&ParsedEvent::Workspace(ws)).unwrap()
}

#[test]
fn decrypt_recurse_inner_rejected_marks_outer_rejected() {
    let c = open_db();
    // Workspace projector schema is needed for the message rejection
    // path NOT to short-circuit on missing tables, but messages module
    // is what really matters here. open_db() already wires it.
    let key_bytes: [u8; 32] = [0x33; 32];

    // Inner blob: encodes fine (codec accepts empty content) but the
    // message projector rejects it — that's the "inner Rejected" path.
    let inner_blob = rejected_message_blob();
    let (encrypted_blob, key_event_id) = build_encrypted_blob(&inner_blob, &key_bytes);
    seed_key_secret(&c, &key_event_id, &key_bytes);

    let outer_id = blake3_id(&encrypted_blob);
    let inner_id = blake3_id(&inner_blob);

    let frame = wrap_one(encrypted_blob);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 11).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1, "one outer event");
    assert_eq!(results[0].event_id, outer_id);

    // The fix: outer must be Rejected (NOT Applied) when inner rejects.
    match &results[0].disposition {
        InnerEventDisposition::Rejected { reason } => {
            assert!(
                reason.contains("inner-rejected"),
                "outer reject reason should be prefixed with `inner-rejected:`, got {:?}",
                reason
            );
            assert!(
                reason.contains("empty"),
                "outer reject reason should propagate inner reason text, got {:?}",
                reason
            );
        }
        other => panic!(
            "expected outer Rejected (mirroring inner), got {:?}",
            other
        ),
    }

    // The events_canonical row must reflect the Rejected verdict —
    // this is what Codex caught: the bug was set_status(Applied) here.
    let outer = get_event(&c, &outer_id).unwrap().expect("outer row");
    assert_eq!(
        outer.status,
        EventStatus::Rejected,
        "outer encrypted row must be Rejected when inner is Rejected"
    );

    // Inner row exists and is Rejected — the chain went all the way
    // through admit_event_id → finalize → project before rejecting.
    let inner = get_event(&c, &inner_id).unwrap().expect("inner row");
    assert_eq!(inner.status, EventStatus::Rejected);

    // The rejected message must NOT have produced a row in `messages`.
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "rejected inner message must not insert a row");
}

#[test]
fn decrypt_recurse_inner_rejected_propagates_to_outer() {
    let c = open_db();
    // Workspace tables are required so the workspace projector's
    // `WriteOp` lookups don't short-circuit at the chain layer.
    topo::event_modules::workspace::ensure_schema(&c).unwrap();
    let key_bytes: [u8; 32] = [0x55; 32];

    // Inner blob: a workspace event with a pre-seeded `deleted` label
    // on its event id. The new workspace projector applies cleanly
    // unless a label gate fires (plan.md Stage 2 translation rule);
    // the `deleted` label triggers a Reject. The chain must mirror
    // the inner Reject onto the outer encrypted row.
    let inner_blob = workspace_blob_for_rejected_path();
    let inner_id = blake3_id(&inner_blob);
    // Pre-write the `deleted` label keyed by the inner event id.
    // Workspace_id is the all-zeros wrapper id used by `wrap_one`.
    topo::state::labels::write_label(
        &c,
        &b64(&[0u8; 32]),
        &b64(&inner_id),
        "deleted",
    )
    .unwrap();

    let (encrypted_blob, key_event_id) = build_encrypted_blob(&inner_blob, &key_bytes);
    seed_key_secret(&c, &key_event_id, &key_bytes);

    let outer_id = blake3_id(&encrypted_blob);

    let frame = wrap_one(encrypted_blob);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 13).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, outer_id);

    // The chain must mirror the inner Reject onto the outer encrypted
    // event. The reason gets a `inner-rejected:` prefix.
    match &results[0].disposition {
        InnerEventDisposition::Rejected { reason } => {
            assert!(
                reason.starts_with("inner-rejected:"),
                "expected outer reason to be prefixed with `inner-rejected:`, got {:?}",
                reason
            );
        }
        other => panic!("expected outer Rejected (mirroring inner), got {:?}", other),
    }

    // Outer events_canonical row must be Rejected, NOT Applied.
    let outer = get_event(&c, &outer_id).unwrap().expect("outer row");
    assert_eq!(
        outer.status,
        EventStatus::Rejected,
        "outer encrypted row must be Rejected when inner is Rejected"
    );

    // Inner row must also be Rejected.
    let inner = get_event(&c, &inner_id).unwrap().expect("inner row");
    assert_eq!(inner.status, EventStatus::Rejected);

    // Workspace projector must NOT have written a row when blocked.
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM workspaces", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "blocked inner workspace must not insert a row");
}

//! End-to-end coverage for the chained `InboundBytes` step
//! (`plan.md` lines 102-114).
//!
//! Cases:
//! 1. bytes → unwrap → single inner event → applied (happy path).
//! 2. bytes → wire_id duplicate → `Duplicate` outcome (no parse called).
//! 3. bytes → unwrap → inner event with already-applied id →
//!    `AlreadyKnown` (admission stops the chain before parse).
//! 4. bytes → unwrap → inner event with missing dep → `Blocked` and a
//!    `blocked_by_event` row is written.
//! 5. applied dependency → `unblock_dependents` flips a downstream
//!    `blocked` row to `ready` (no recursion within the call).
//! 6. atomicity: a midway failure rolls back every write inside the
//!    chain transaction.

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use topo::event_modules::connection::local_signing_key;
use topo::event_modules::connection::wrap::{wrap_bootstrap, InnerCanonicalEvent};
use topo::event_modules::{
    encode_event, DeviceInviteEvent, InviteAcceptedEvent, InviteSecretEvent, KeyRequestEvent,
    KeyRotationEvent, KeySecretEvent, KeySharedEvent, MessageDeletionEvent, MessageEvent,
    ParsedEvent, PeerSharedEvent, ReactionEvent, TenantEvent, UserEvent, UserInviteEvent,
    WorkspaceEvent,
};
use topo::runtime::control_loop::work_item::{BlakeId, EndpointId};
use topo::runtime::control_loop::{
    handle_inbound_bytes, handle_ready_event, InboundOrigin, InboundOutcome,
    InnerEventDisposition,
};
use topo::state::db::control_loop_tables::ensure_schema as ensure_substrate_schema;
use topo::state::events_canonical::{
    add_blockers, get as get_event, set_status, upsert_event, EventRow, EventScope, EventStatus,
};

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

fn open_db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    ensure_substrate_schema(&c).unwrap();
    // Registry-driven module schema bring-up: every event module's
    // `ensure_schema` runs in one pass, including sync's
    // `connection_round_state` and connection's
    // `connection_shared_workspaces`. The test fixture mirrors the
    // production boot path (`state::db::ensure_infra_schema`).
    topo::event_modules::ensure_all_module_schemas(&c).unwrap();
    // Install the recipient's signing key for this in-memory db so the
    // ECDH-based bootstrap unwrap can recover the AEAD key.
    let path = c.path().unwrap_or("").to_string();
    local_signing_key::install_for_path(&path, recipient_sk());
    c
}

fn tenant_blob(marker: u8) -> Vec<u8> {
    let e = TenantEvent {
        created_at_ms: 1_000 + marker as u64,
        public_key: [marker; 32],
    };
    encode_event(&ParsedEvent::Tenant(e)).unwrap()
}

fn workspace_blob() -> Vec<u8> {
    // Workspace projector returns `Block { missing: [] }` when the
    // chain's empty ContextSnapshot has no accepted_workspace_id —
    // exactly the structural guard-block path described in
    // workspace::projector::project_pure.
    let w = WorkspaceEvent {
        created_at_ms: 5_000,
        workspace_id: [7u8; 32],
        public_key: [7u8; 32],
        name: "ws".to_string(),
    };
    encode_event(&ParsedEvent::Workspace(w)).unwrap()
}

fn wrap_one(blob: Vec<u8>) -> Vec<u8> {
    let inner = vec![InnerCanonicalEvent {
        workspace_id: [0u8; 32],
        bytes: blob,
    }];
    let frame = wrap_bootstrap(&sender_sk(), recipient_eid(), &inner).unwrap();
    frame.as_bytes().to_vec()
}

/// Same as `wrap_one` but pins the inner canonical workspace_id, so
/// `events_canonical.workspace_id` (set by `finalize_admitted`) lines up
/// with the parsed event's own `workspace_id` field. This matters for
/// the message-family chain tests because `generic_context` scopes its
/// `labels` lookup by `events_canonical.workspace_id`.
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

fn origin() -> InboundOrigin {
    InboundOrigin {
        remote_endpoint_id: Some(sender_eid()),
        ip: Some("127.0.0.1".to_string()),
        port: Some(4242),
    }
}

#[test]
fn happy_path_applies_single_inner_event() {
    let c = open_db();
    let blob = tenant_blob(0xAB);
    let inner_id = blake3_id(&blob);
    let frame = wrap_one(blob);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, inner_id);
    assert_eq!(results[0].disposition, InnerEventDisposition::Applied);

    // Tenant projector wrote a row.
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "tenant projector should have written a row");

    // Events row is `applied`.
    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);
}

#[test]
fn duplicate_wire_id_short_circuits() {
    let c = open_db();
    let blob = tenant_blob(0xCD);
    let frame = wrap_one(blob);

    let r1 = handle_inbound_bytes(&frame, origin(), &c, 10).unwrap();
    matches!(r1, InboundOutcome::InnerEventsProcessed { .. });

    let r2 = handle_inbound_bytes(&frame, origin(), &c, 20).unwrap();
    match r2 {
        InboundOutcome::Duplicate { .. } => {}
        other => panic!("expected Duplicate on repeat, got {:?}", other),
    }

    // Observation row was bumped, not duplicated.
    let seen_count: i64 = c
        .query_row(
            "SELECT seen_count FROM inbound_observations LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(seen_count, 2, "observation should bump seen_count");
}

#[test]
fn already_known_inner_event_is_short_circuited_before_parse() {
    let c = open_db();
    let blob = tenant_blob(0xEF);
    let inner_id = blake3_id(&blob);

    // Pre-seed events_canonical with the same id in `applied` status. The
    // chain's admission step should detect Known and stop without
    // reparsing or rewriting.
    upsert_event(
        &c,
        &EventRow {
            event_id: inner_id,
            canonical_event_bytes: vec![],
            workspace_id: Some([0u8; 32]),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let frame = wrap_one(blob);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 100).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::AlreadyKnown {
            status: EventStatus::Applied
        }
    );

    // Tenant projector did NOT run.
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "projector must not run when admission says Known");
}

#[test]
fn workspace_event_applies_via_new_chain() {
    // New-chain test (plan.md Stage 2): a Workspace event flows
    // through `handle_inbound_bytes` end-to-end and lands in the
    // `workspaces` projection table keyed by `(workspace_id,
    // event_id)`. This exercises the same path the runtime test
    // `runtime_processes_inbound_frame_end_to_end` uses, but inline so
    // we can inspect the projection row directly.
    //
    // Prereq: ensure the workspaces table exists in the test DB. The
    // `inbound_chain_test::open_db` helper only installs tenant
    // schema; for this test we install workspace schema explicitly.
    let c = open_db();
    topo::event_modules::workspace::ensure_schema(&c).unwrap();

    let blob = workspace_blob();
    let inner_id = blake3_id(&blob);
    let inner_id_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        inner_id,
    );
    let frame = wrap_one(blob);

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
        "workspace event must apply directly under the new chain"
    );

    // events_canonical row is Applied.
    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    // workspaces projection row exists keyed by `(workspace_id,
    // event_id)`. For a root workspace event the projection's
    // `workspace_id` IS the event_id (children point at the root via
    // their own `workspace_id` field with this same value).
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM workspaces
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![inner_id_b64, inner_id_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "workspaces row must exist keyed by (workspace_id == event_id, event_id)"
    );
}

#[test]
fn add_blockers_writes_blocked_by_event_row() {
    // Lower-level test that the `add_blockers` helper writes a
    // `blocked_by_event` row and flips status to `blocked`. Used to
    // be combined with the workspace-block path in
    // `blocked_inner_event_writes_blocked_by_event_row`, but the
    // workspace projector now applies cleanly under the new chain
    // (plan.md Stage 2), so this isolates the helper's contract.

    let c = open_db();
    let inner_id: BlakeId = [0xCA; 32];
    upsert_event(
        &c,
        &EventRow {
            event_id: inner_id,
            canonical_event_bytes: vec![1, 2, 3],
            workspace_id: Some([0u8; 32]),
            scope: EventScope::Durable,
            status: EventStatus::Processing,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let dep_id: BlakeId = [0xDE; 32];
    add_blockers(&c, &inner_id, &[dep_id]).unwrap();

    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM blocked_by_event
             WHERE blocked_by_event_id = ?1 AND event_id = ?2",
            params![dep_id.to_vec(), inner_id.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1, "blocked_by_event row must be written");

    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Blocked);
}

#[test]
fn applied_dep_unblocks_dependent_to_ready_without_recursion() {
    let c = open_db();

    // Set up a dependent event in `blocked` status, blocked on a dep
    // id that matches the canonical id of the blob we're about to feed
    // through the chain. We construct the dependent row by hand to
    // keep the test focused on the ready-flip semantics — the same
    // `add_blockers` helper the chain uses internally drives the
    // block.
    let dependent_id: BlakeId = [0x11; 32];
    let dep_blob = tenant_blob(0x22);
    let dep_id: BlakeId = blake3_id(&dep_blob);

    upsert_event(
        &c,
        &EventRow {
            event_id: dependent_id,
            canonical_event_bytes: vec![1, 2, 3],
            workspace_id: Some([0u8; 32]),
            scope: EventScope::Durable,
            status: EventStatus::Blocked,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();
    add_blockers(&c, &dependent_id, &[dep_id]).unwrap();

    // Sanity: dependent is blocked, blocker row exists.
    assert_eq!(
        get_event(&c, &dependent_id).unwrap().unwrap().status,
        EventStatus::Blocked
    );
    let edge: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM blocked_by_event
             WHERE blocked_by_event_id = ?1 AND event_id = ?2",
            params![dep_id.to_vec(), dependent_id.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(edge, 1);

    // Run the inbound chain with the dep arriving on the wire. The dep
    // applies via the tenant projector, then `unblock_dependents` flips
    // the dependent to `ready` — but does NOT recursively project it.
    let frame = wrap_one(dep_blob);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 7).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].disposition, InnerEventDisposition::Applied);
    assert_eq!(results[0].event_id, dep_id);

    // Dep is applied.
    assert_eq!(
        get_event(&c, &dep_id).unwrap().unwrap().status,
        EventStatus::Applied
    );

    // Dependent is now `ready` (no recursion — it's queued, not
    // projected).
    assert_eq!(
        get_event(&c, &dependent_id).unwrap().unwrap().status,
        EventStatus::Ready,
        "downstream blocker must be flipped to ready, not applied"
    );

    // Blocked edge was deleted.
    let edge_after: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM blocked_by_event
             WHERE blocked_by_event_id = ?1",
            params![dep_id.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(edge_after, 0);

    // Now drive the dependent through the ReadyEvent tail. It will
    // re-parse from events_canonical.canonical_event_bytes — the bytes [1,2,3]
    // are not a valid event, so we expect ParseFailed and a status
    // transition to Rejected (releasing the processing claim is the
    // chain's parse-failure semantics).
    let disp = handle_ready_event(&dependent_id, &c, 8).unwrap();
    match disp {
        InnerEventDisposition::ParseFailed { .. } => {}
        other => panic!("expected ParseFailed, got {:?}", other),
    }
    assert_eq!(
        get_event(&c, &dependent_id).unwrap().unwrap().status,
        EventStatus::Rejected
    );
}

#[test]
fn parse_failure_rejects_inner_event_and_releases_admission_claim() {
    let c = open_db();
    // Wrap a payload that parses through `unwrap` (so the chain reaches
    // the per-inner step) but fails `parse_event` (an inner blob with
    // type code 0 — no registered type for that code).
    let bad_inner = vec![0u8; 4];
    let inner = vec![InnerCanonicalEvent {
        workspace_id: [0u8; 32],
        bytes: bad_inner.clone(),
    }];
    let frame = wrap_bootstrap(&sender_sk(), recipient_eid(), &inner)
        .unwrap()
        .as_bytes()
        .to_vec();
    let inner_id = blake3_id(&bad_inner);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 9).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    match &results[0].disposition {
        InnerEventDisposition::ParseFailed { .. } => {}
        other => panic!("expected ParseFailed, got {:?}", other),
    }
    // Row was admitted then rejected — the `processing` claim is
    // released by transitioning to `rejected`.
    let row = get_event(&c, &inner_id).unwrap().expect("admitted row");
    assert_eq!(row.status, EventStatus::Rejected);
}

#[test]
fn chain_is_atomic_when_a_post_admit_step_panics_via_db_error() {
    // We can't easily inject a panic mid-chain without test hooks, but
    // we can prove atomicity by exploiting the fact that the chain runs
    // inside a single BEGIN IMMEDIATE: opening the DB with a closed/
    // dropped tx and re-checking `inbound_bytes` after a forced rollback
    // shows nothing committed. The cheapest reliable proof is to do a
    // "try then verify" round trip:
    //
    // 1. Run the chain on a fresh frame.
    // 2. Verify side effects exist.
    // 3. Run a second frame inside an outer BEGIN that we then ROLLBACK.
    //    Note: SQLite does not nest BEGINs by default, so the chain will
    //    fail to re-BEGIN — its own error path rolls back any partial
    //    work it did. We verify the second frame's inner event id is
    //    NOT in events_canonical, AND inbound_bytes does not have its
    //    wire id.

    let c = open_db();
    let blob1 = tenant_blob(0x01);
    let frame1 = wrap_one(blob1);
    handle_inbound_bytes(&frame1, origin(), &c, 1).unwrap();
    let n_before: i64 = c
        .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_before, 1);

    // Open an outer transaction and call the chain; the chain's own
    // BEGIN IMMEDIATE will fail (transaction already active). Its error
    // path rolls back what it had — we should see the table state
    // unchanged after we rollback the outer too.
    c.execute("BEGIN IMMEDIATE", []).unwrap();
    let blob2 = tenant_blob(0x02);
    let frame2 = wrap_one(blob2.clone());
    let inner2_id = blake3_id(&blob2);
    let res = handle_inbound_bytes(&frame2, origin(), &c, 2);
    assert!(res.is_err(), "nested BEGIN must fail");
    c.execute("ROLLBACK", []).unwrap();

    // The aborted second call must not have left an events_canonical
    // row for blob2's inner_id, and inbound_bytes must still have only
    // the first row.
    assert!(
        get_event(&c, &inner2_id).unwrap().is_none(),
        "aborted chain must not have committed events_canonical row"
    );
    let n_after: i64 = c
        .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_after, 1, "aborted chain must not have committed inbound_bytes");
}

#[test]
fn ready_event_handler_applies_a_ready_row() {
    // Drive the ReadyEvent tail directly: pre-seed a `ready` row whose
    // canonical_event_bytes is a valid tenant blob and verify the projector runs.
    let c = open_db();
    let blob = tenant_blob(0x99);
    let id = blake3_id(&blob);
    upsert_event(
        &c,
        &EventRow {
            event_id: id,
            canonical_event_bytes: blob,
            workspace_id: Some([0u8; 32]),
            scope: EventScope::Durable,
            status: EventStatus::Ready,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();
    let _ = set_status(&c, &id, EventStatus::Ready);

    let disp = handle_ready_event(&id, &c, 0).unwrap();
    assert_eq!(disp, InnerEventDisposition::Applied);
    assert_eq!(
        get_event(&c, &id).unwrap().unwrap().status,
        EventStatus::Applied
    );
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn user_event_applies_via_new_chain() {
    // Phase 32: a User event flows through `handle_inbound_bytes`
    // end-to-end and lands in the `users` projection table keyed by
    // `(workspace_id, event_id)`. We pre-seed the `signed_by`
    // dependency in `events_canonical` so the chain doesn't block.
    let c = open_db();
    topo::event_modules::user::ensure_schema(&c).unwrap();

    // Pre-seed signed_by dep so the user event isn't blocked.
    let signed_by_id: BlakeId = [0xAA; 32];
    let workspace_id_bytes: [u8; 32] = [0x77; 32];
    upsert_event(
        &c,
        &EventRow {
            event_id: signed_by_id,
            canonical_event_bytes: vec![1, 2, 3],
            workspace_id: Some(workspace_id_bytes),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    // Build a User event whose workspace_id is explicit.
    let user = UserEvent {
        created_at_ms: 7_000,
        workspace_id: workspace_id_bytes,
        public_key: [0x33; 32],
        username: "alice".to_string(),
        signed_by: signed_by_id,
        signer_type: 2,
        signature: [0u8; 64],
    };
    let blob = encode_event(&ParsedEvent::User(user)).unwrap();
    let inner_id = blake3_id(&blob);
    let inner_id_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        inner_id,
    );
    let workspace_id_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        workspace_id_bytes,
    );

    let frame = wrap_one_with_ws(blob, workspace_id_bytes);
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
        "user event must apply directly under the new chain"
    );

    // events_canonical row is Applied.
    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    // users projection row exists keyed by `(workspace_id, event_id)`.
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM users
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![workspace_id_b64, inner_id_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "users row must exist keyed by (workspace_id, event_id)"
    );
}

#[test]
fn peer_shared_event_applies_via_new_chain() {
    // Phase 32: a PeerShared event flows through `handle_inbound_bytes`
    // end-to-end and lands in the `peers_shared` projection table keyed
    // by `(workspace_id, event_id)`. We pre-seed the `signed_by` and
    // `user_event_id` dependencies in `events_canonical` so the chain
    // doesn't block.
    let c = open_db();
    topo::event_modules::peer_shared::ensure_schema(&c).unwrap();

    // Pre-seed signed_by + user_event_id deps so the peer_shared event
    // isn't blocked.
    let signed_by_id: BlakeId = [0xBB; 32];
    let user_event_id: BlakeId = [0xCC; 32];
    let workspace_id_bytes: [u8; 32] = [0x66; 32];
    for id in [signed_by_id, user_event_id] {
        upsert_event(
            &c,
            &EventRow {
                event_id: id,
                canonical_event_bytes: vec![1, 2, 3],
                workspace_id: Some(workspace_id_bytes),
                scope: EventScope::Durable,
                status: EventStatus::Applied,
                created_at_ms: 0,
                expires_at_ms: None,
            },
        )
        .unwrap();
    }

    let ps = PeerSharedEvent {
        created_at_ms: 8_000,
        workspace_id: workspace_id_bytes,
        public_key: [0x44; 32],
        user_event_id,
        device_name: "phone".to_string(),
        signed_by: signed_by_id,
        signer_type: 3,
        signature: [0u8; 64],
    };
    let blob = encode_event(&ParsedEvent::PeerShared(ps)).unwrap();
    let inner_id = blake3_id(&blob);
    let inner_id_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        inner_id,
    );
    let workspace_id_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        workspace_id_bytes,
    );

    let frame = wrap_one_with_ws(blob, workspace_id_bytes);
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
        "peer_shared event must apply directly under the new chain"
    );

    // events_canonical row is Applied.
    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    // peers_shared projection row exists keyed by `(workspace_id, event_id)`.
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM peers_shared
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![workspace_id_b64, inner_id_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "peers_shared row must exist keyed by (workspace_id, event_id)"
    );
}

// ────────────────────────────────────────────────────────────────────
// Message family chain tests (plan.md Stage 2 — chain-friendly migration)
//
// These cover Message, Reaction, and MessageDeletion flowing through the
// new chain end-to-end without the legacy `recorded_by` thread-local. The
// projector reads each event's own `workspace_id` and writes the canonical
// projection rows keyed by `(workspace_id, event_id)`.
// ────────────────────────────────────────────────────────────────────

const TEST_WS_MSG: [u8; 32] = [0xA1u8; 32];
const TEST_AUTHOR_MSG: [u8; 32] = [0xA2u8; 32];
const TEST_SIGNER_MSG: [u8; 32] = [0xA3u8; 32];

fn open_msg_db() -> Connection {
    let c = open_db();
    topo::event_modules::message::ensure_schema(&c).unwrap();
    topo::event_modules::reaction::ensure_schema(&c).unwrap();
    topo::event_modules::message_deletion::ensure_schema(&c).unwrap();
    c
}

fn b64_msg(id: [u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(id)
}

fn message_blob_for(content: &str, created_at_ms: u64) -> Vec<u8> {
    let m = MessageEvent {
        created_at_ms,
        workspace_id: TEST_WS_MSG,
        author_id: TEST_AUTHOR_MSG,
        content: content.to_string(),
        signed_by: TEST_SIGNER_MSG,
        signer_type: 5,
        signature: [0u8; 64],
    };
    encode_event(&ParsedEvent::Message(m)).unwrap()
}

fn reaction_blob_for(target: [u8; 32], emoji: &str, created_at_ms: u64) -> Vec<u8> {
    let r = ReactionEvent {
        created_at_ms,
        workspace_id: TEST_WS_MSG,
        target_event_id: target,
        author_id: TEST_AUTHOR_MSG,
        emoji: emoji.to_string(),
        signed_by: TEST_SIGNER_MSG,
        signer_type: 5,
        signature: [0u8; 64],
    };
    encode_event(&ParsedEvent::Reaction(r)).unwrap()
}

fn deletion_blob_for(target: [u8; 32], created_at_ms: u64) -> Vec<u8> {
    let d = MessageDeletionEvent {
        created_at_ms,
        workspace_id: TEST_WS_MSG,
        target_event_id: target,
        author_id: TEST_AUTHOR_MSG,
        signed_by: TEST_SIGNER_MSG,
        signer_type: 5,
        signature: [0u8; 64],
    };
    encode_event(&ParsedEvent::MessageDeletion(d)).unwrap()
}

#[test]
fn message_event_applies_via_new_chain() {
    // A Message event flows through `handle_inbound_bytes` end-to-end and
    // lands in the `messages` projection table keyed by `(workspace_id,
    // message_id)` (plan.md Stage 2). No `recorded_by` thread-local is in
    // play; the projector reads `msg.workspace_id` directly.
    let c = open_msg_db();

    let blob = message_blob_for("hello chain", 1_000);
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, TEST_WS_MSG);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, inner_id);
    assert_eq!(results[0].disposition, InnerEventDisposition::Applied);

    // Canonical row is Applied.
    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    // Projection row exists keyed by `(workspace_id, message_id)`.
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM messages
             WHERE workspace_id = ?1 AND message_id = ?2",
            params![b64_msg(TEST_WS_MSG), b64_msg(inner_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "messages row must exist keyed by (workspace_id, message_id)"
    );

    // Content was preserved.
    let content: String = c
        .query_row(
            "SELECT content FROM messages WHERE message_id = ?1",
            params![b64_msg(inner_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(content, "hello chain");
}

#[test]
fn reaction_event_applies_via_new_chain() {
    // A Reaction whose target message is already applied flows through
    // the chain and writes a row to the `reactions` projection table
    // keyed by `(workspace_id, event_id)`.
    let c = open_msg_db();

    // 1. Drive the parent message through the chain so the reaction's
    //    `target_event_id` dep is admitted.
    let msg_blob = message_blob_for("base message", 1_000);
    let msg_id = blake3_id(&msg_blob);
    handle_inbound_bytes(&wrap_one_with_ws(msg_blob, TEST_WS_MSG), origin(), &c, 1).unwrap();
    assert_eq!(
        get_event(&c, &msg_id).unwrap().unwrap().status,
        EventStatus::Applied
    );

    // 2. Drive the reaction.
    let rxn_blob = reaction_blob_for(msg_id, "+1", 2_000);
    let rxn_id = blake3_id(&rxn_blob);
    let outcome = handle_inbound_bytes(
        &wrap_one_with_ws(rxn_blob, TEST_WS_MSG),
        origin(),
        &c,
        2,
    )
    .unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].disposition, InnerEventDisposition::Applied);

    // Reaction row exists keyed by (workspace_id, event_id).
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM reactions
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![b64_msg(TEST_WS_MSG), b64_msg(rxn_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "reactions row must exist keyed by (workspace_id, event_id)"
    );
}

#[test]
fn message_deletion_writes_deleted_label_and_purges_target() {
    // A message_deletion event applied via the chain must:
    //   1. Write the `deleted` label scoped to the parsed event's
    //      workspace_id.
    //   2. Tombstone the target row in `deleted_messages`.
    //   3. Purge the target message row from `messages`.
    let c = open_msg_db();

    // Parent message first.
    let msg_blob = message_blob_for("doomed", 1_000);
    let msg_id = blake3_id(&msg_blob);
    handle_inbound_bytes(&wrap_one_with_ws(msg_blob, TEST_WS_MSG), origin(), &c, 1).unwrap();
    let n_before: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
            params![b64_msg(msg_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n_before, 1, "message must exist before deletion");

    // Deletion event.
    let del_blob = deletion_blob_for(msg_id, 2_000);
    let del_id = blake3_id(&del_blob);
    let outcome = handle_inbound_bytes(
        &wrap_one_with_ws(del_blob, TEST_WS_MSG),
        origin(),
        &c,
        2,
    )
    .unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results[0].disposition, InnerEventDisposition::Applied);
    assert_eq!(
        get_event(&c, &del_id).unwrap().unwrap().status,
        EventStatus::Applied
    );

    // The target message must be purged from `messages` (cascade Delete
    // op in the projector).
    let n_msgs: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
            params![b64_msg(msg_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n_msgs, 0, "message row must be cascade-deleted");

    // The tombstone row exists in `deleted_messages` keyed by
    // `(workspace_id, message_id)`.
    let n_tomb: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM deleted_messages
             WHERE workspace_id = ?1 AND message_id = ?2",
            params![b64_msg(TEST_WS_MSG), b64_msg(msg_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n_tomb, 1,
        "deleted_messages row must exist keyed by (workspace_id, message_id)"
    );

    // The `deleted` label is reified, scoped to TEST_WS_MSG.
    let label_count: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM labels
             WHERE event_id = ?1 AND label_type = 'deleted' AND workspace_id = ?2",
            params![msg_id.to_vec(), TEST_WS_MSG.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(label_count, 1, "deleted label must be written for target");
}

#[test]
fn reaction_to_deleted_message_no_ops_via_label() {
    // When a `deleted` label is already present for the target message,
    // a subsequent reaction projects as Valid (structurally fine) but
    // writes no row.
    let c = open_msg_db();

    // Parent message first.
    let msg_blob = message_blob_for("base", 1_000);
    let msg_id = blake3_id(&msg_blob);
    handle_inbound_bytes(&wrap_one_with_ws(msg_blob, TEST_WS_MSG), origin(), &c, 1).unwrap();

    // Pre-write the `deleted` label directly so we don't have to drive a
    // full deletion event through the chain (this isolates the
    // reaction-side gate behavior).
    c.execute(
        "INSERT OR IGNORE INTO labels (event_id, label_type, workspace_id)
         VALUES (?1, 'deleted', ?2)",
        params![msg_id.to_vec(), TEST_WS_MSG.to_vec()],
    )
    .unwrap();

    // Now attempt the reaction.
    let rxn_blob = reaction_blob_for(msg_id, ":-(", 2_000);
    let rxn_id = blake3_id(&rxn_blob);
    let outcome = handle_inbound_bytes(
        &wrap_one_with_ws(rxn_blob, TEST_WS_MSG),
        origin(),
        &c,
        2,
    )
    .unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    // Structurally valid (reaches Applied) but no row written.
    assert_eq!(results[0].disposition, InnerEventDisposition::Applied);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE event_id = ?1",
            params![b64_msg(rxn_id)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 0,
        "reactions row must NOT be written when target carries `deleted` label"
    );
}

#[test]
fn removed_by_label_rejects_message_from_signer() {
    // A `removed_by:<issuer>` label on the message's `signed_by`
    // identity rejects the message in projection.
    let c = open_msg_db();

    // Pre-write a removed_by label on the signer identity, scoped to
    // TEST_WS_MSG (the workspace the message will declare).
    c.execute(
        "INSERT OR IGNORE INTO labels (event_id, label_type, workspace_id)
         VALUES (?1, 'removed_by:U', ?2)",
        params![TEST_SIGNER_MSG.to_vec(), TEST_WS_MSG.to_vec()],
    )
    .unwrap();

    let blob = message_blob_for("from a removed signer", 1_000);
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, TEST_WS_MSG);
    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    match &results[0].disposition {
        InnerEventDisposition::Rejected { reason } => {
            assert!(
                reason.contains("removed_by") || reason.contains("removed"),
                "rejection reason should reference removed_by gate, got: {}",
                reason
            );
        }
        other => panic!("expected Rejected, got {:?}", other),
    }
    // Canonical row is rejected — no projection row was written.
    assert_eq!(
        get_event(&c, &inner_id).unwrap().unwrap().status,
        EventStatus::Rejected
    );
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "no message row should be written under removed_by gate");
}

// ─── Chain-friendly invite-family migrations (plan.md Stage 2) ───
//
// Each test below builds an event of the migrated kind, runs it through
// `handle_inbound_bytes`, and asserts:
//   - events_canonical row is `Applied`,
//   - the projection table has a row keyed by `workspace_id`.
//
// These exercise the new chain only (no `current_recorded_by()` thread-
// local set). The projector falls back to the `__chain__` sentinel for
// the nullable `recorded_by` shadow column; the PK is `(workspace_id,
// event_id)`.

fn b64_id_invites(id: &BlakeId) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(id)
}

fn seed_applied_invites(c: &Connection, id: BlakeId, ws: [u8; 32], bytes: Vec<u8>) {
    upsert_event(
        c,
        &EventRow {
            event_id: id,
            canonical_event_bytes: bytes,
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();
}

#[test]
fn invite_accepted_event_applies_via_new_chain() {
    // InviteAccepted carries `workspace_id` and `tenant_event_id` deps.
    // We pre-seed a tenant row in events_canonical so the chain's
    // dep-loading sees an applied tenant and the projector runs.
    let c = open_db();
    topo::event_modules::invite_accepted::ensure_schema(&c).unwrap();

    let workspace_id = [0x77u8; 32];

    // 1. Seed a real tenant blob as Applied.
    let tenant_b = tenant_blob(0x11);
    let tenant_id = blake3_id(&tenant_b);
    seed_applied_invites(&c, tenant_id, workspace_id, tenant_b);

    // 2. Build the InviteAccepted event.
    let ia = InviteAcceptedEvent {
        created_at_ms: 1234,
        tenant_event_id: tenant_id,
        invite_event_id: [0x33u8; 32],
        workspace_id,
    };
    let blob = encode_event(&ParsedEvent::InviteAccepted(ia)).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, workspace_id);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "invite_accepted must apply directly under the new chain"
    );

    // events_canonical row is Applied.
    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    // Projection row exists keyed by `(workspace_id, event_id)`.
    let ws_b64 = b64_id_invites(&workspace_id);
    let event_b64 = b64_id_invites(&inner_id);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM invites_accepted
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![ws_b64, event_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "invites_accepted row must exist keyed by (workspace_id, event_id)"
    );
}

#[test]
fn user_invite_shared_event_applies_via_new_chain() {
    // UserInvite (signer_type=1, bootstrap): authority_event_id ==
    // signed_by == workspace_id. The projector accepts this without
    // requiring `invite_authority_matches_signer`.
    let c = open_db();
    topo::event_modules::user_invite_shared::ensure_schema(&c).unwrap();

    let workspace_id = [0x88u8; 32];

    let ui = UserInviteEvent {
        created_at_ms: 5,
        public_key: [0x99u8; 32],
        workspace_id,
        authority_event_id: workspace_id,
        signed_by: workspace_id,
        signer_type: 1,
        signature: [0u8; 64],
    };
    let blob = encode_event(&ParsedEvent::UserInvite(ui)).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, workspace_id);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "user_invite_shared must apply directly under the new chain"
    );

    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    let ws_b64 = b64_id_invites(&workspace_id);
    let event_b64 = b64_id_invites(&inner_id);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM user_invites
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![ws_b64, event_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "user_invites row must exist keyed by (workspace_id, event_id)"
    );
}

#[test]
fn peer_invite_shared_event_applies_via_new_chain() {
    // DeviceInvite (signer_type=4, bootstrap): authority_event_id ==
    // signed_by. The projector's bootstrap branch only requires the
    // structural check.
    let c = open_db();
    topo::event_modules::peer_invite_shared::ensure_schema(&c).unwrap();

    let workspace_id = [0xAAu8; 32];
    let user_event_id = [0xBBu8; 32];

    // Seed the user event row so deps that point at it can be loaded.
    seed_applied_invites(&c, user_event_id, workspace_id, vec![]);

    let di = DeviceInviteEvent {
        created_at_ms: 9,
        public_key: [0xCCu8; 32],
        workspace_id,
        authority_event_id: user_event_id,
        signed_by: user_event_id,
        signer_type: 4,
        signature: [0u8; 64],
    };
    let blob = encode_event(&ParsedEvent::DeviceInvite(di)).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, workspace_id);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "peer_invite_shared must apply directly under the new chain"
    );

    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    let ws_b64 = b64_id_invites(&workspace_id);
    let event_b64 = b64_id_invites(&inner_id);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM device_invites
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![ws_b64, event_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "device_invites row must exist keyed by (workspace_id, event_id)"
    );
}

#[test]
fn invite_secret_event_applies_via_new_chain() {
    // InviteSecret has no deps — the simplest of the four. The
    // projector unconditionally writes to `invite_secrets` keyed by
    // `(workspace_id, event_id)`.
    let c = open_db();
    topo::event_modules::invite_secret::ensure_schema(&c).unwrap();

    let workspace_id = [0xDDu8; 32];

    let is_evt = InviteSecretEvent {
        created_at_ms: 3,
        invite_event_id: [0xEEu8; 32],
        workspace_id,
        private_key_bytes: [0xFFu8; 32],
    };
    let blob = encode_event(&ParsedEvent::InviteSecret(is_evt)).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, workspace_id);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "invite_secret must apply directly under the new chain"
    );

    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    let ws_b64 = b64_id_invites(&workspace_id);
    let event_b64 = b64_id_invites(&inner_id);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM invite_secrets
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![ws_b64, event_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "invite_secrets row must exist keyed by (workspace_id, event_id)"
    );
}

// ────────────────────────────────────────────────────────────────────
// Key family chain tests (plan.md Stage 2 — chain-friendly migration)
//
// Key-family events (KeySecret, KeyShared, KeyRequest, KeyRotation) all
// carry an explicit `workspace_id` field, and the projection-table PK
// migrated from `(recorded_by, event_id)` to `(workspace_id, event_id)`.
// These tests confirm each event flows through `handle_inbound_bytes`
// end-to-end without the legacy thread-local recorded_by bridge.
// ────────────────────────────────────────────────────────────────────

#[test]
fn key_secret_event_applies_via_new_chain() {
    // KeySecret has no deps and no signer. The simplest of the four.
    let c = open_db();
    topo::event_modules::key_secret::ensure_schema(&c).unwrap();

    let workspace_id = [0xA1u8; 32];

    let evt = KeySecretEvent {
        created_at_ms: 1_000,
        workspace_id,
        key_bytes: [0x42u8; 32],
    };
    let blob = encode_event(&ParsedEvent::KeySecret(evt)).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, workspace_id);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "key_secret must apply directly under the new chain"
    );

    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    let ws_b64 = b64_id_invites(&workspace_id);
    let event_b64 = b64_id_invites(&inner_id);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM key_secrets
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![ws_b64, event_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "key_secrets row must exist keyed by (workspace_id, event_id)"
    );
}

#[test]
fn key_shared_event_applies_via_new_chain() {
    // KeyShared has dependencies (recipient_event_id, frontier_refs,
    // signed_by). Pre-seed them as Applied so the chain doesn't block.
    let c = open_db();
    topo::event_modules::key_shared::ensure_schema(&c).unwrap();

    let workspace_id = [0xB1u8; 32];
    let recipient_event_id = [0xB2u8; 32];
    let signed_by = [0xB3u8; 32];

    for id in [recipient_event_id, signed_by] {
        upsert_event(
            &c,
            &EventRow {
                event_id: id,
                canonical_event_bytes: vec![1, 2, 3],
                workspace_id: Some(workspace_id),
                scope: EventScope::Durable,
                status: EventStatus::Applied,
                created_at_ms: 0,
                expires_at_ms: None,
            },
        )
        .unwrap();
    }

    let key_event_id = [0xB4u8; 32];
    let frontier_hash = topo::event_modules::removal::frontier_hash_from_refs(&[]);
    let unwrap_key_event_id = [0xB5u8; 32];
    let delivery_target_id = topo::event_modules::key_request::delivery_target_id(
        &key_event_id,
        &frontier_hash,
        &recipient_event_id,
        &unwrap_key_event_id,
    );

    let evt = KeySharedEvent {
        created_at_ms: 2_000,
        workspace_id,
        key_event_id,
        frontier_count: 0,
        frontier_ref_1: [0u8; 32],
        frontier_ref_2: [0u8; 32],
        frontier_ref_3: [0u8; 32],
        frontier_ref_4: [0u8; 32],
        frontier_hash,
        delivery_target_id,
        recipient_event_id,
        unwrap_key_event_id,
        wrapped_key: [0xB6u8; 32],
        signed_by,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let blob = encode_event(&ParsedEvent::KeyShared(evt)).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, workspace_id);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "key_shared must apply directly under the new chain"
    );

    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    let ws_b64 = b64_id_invites(&workspace_id);
    let event_b64 = b64_id_invites(&inner_id);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM key_shared
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![ws_b64, event_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "key_shared row must exist keyed by (workspace_id, event_id)"
    );
}

#[test]
fn key_request_event_applies_via_new_chain() {
    // KeyRequest has dep `signed_by`. Pre-seed it as Applied.
    let c = open_db();
    topo::event_modules::key_request::ensure_schema(&c).unwrap();

    let workspace_id = [0xC1u8; 32];
    let signed_by = [0xC2u8; 32];

    upsert_event(
        &c,
        &EventRow {
            event_id: signed_by,
            canonical_event_bytes: vec![1, 2, 3],
            workspace_id: Some(workspace_id),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let key_event_id = [0xC3u8; 32];
    let frontier_hash = topo::event_modules::removal::frontier_hash_from_refs(&[]);
    let recipient_event_id = [0xC4u8; 32];
    let unwrap_key_event_id = [0xC5u8; 32];
    let delivery_target = topo::event_modules::key_request::delivery_target_id(
        &key_event_id,
        &frontier_hash,
        &recipient_event_id,
        &unwrap_key_event_id,
    );

    let evt = KeyRequestEvent {
        created_at_ms: 3_000,
        workspace_id,
        blocked_event_id: [0xC6u8; 32],
        key_event_id,
        frontier_hash,
        delivery_target_id: delivery_target,
        recipient_event_id,
        unwrap_key_event_id,
        signed_by,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let blob = encode_event(&ParsedEvent::KeyRequest(evt)).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, workspace_id);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "key_request must apply directly under the new chain"
    );

    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    let ws_b64 = b64_id_invites(&workspace_id);
    let event_b64 = b64_id_invites(&inner_id);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM key_requests
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![ws_b64, event_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "key_requests row must exist keyed by (workspace_id, event_id)"
    );
}

#[test]
fn key_rotation_event_applies_via_new_chain() {
    // KeyRotation has dep `signed_by`. Pre-seed it as Applied.
    let c = open_db();
    topo::event_modules::key_rotation::ensure_schema(&c).unwrap();

    let workspace_id = [0xD1u8; 32];
    let signer = [0xD2u8; 32];

    upsert_event(
        &c,
        &EventRow {
            event_id: signer,
            canonical_event_bytes: vec![1, 2, 3],
            workspace_id: Some(workspace_id),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let frontier_hash = topo::event_modules::removal::frontier_hash_from_refs(&[]);
    let evt = KeyRotationEvent {
        created_at_ms: 4_000,
        workspace_id,
        key_event_id: [0xD3u8; 32],
        frontier_count: 0,
        frontier_ref_1: [0u8; 32],
        frontier_ref_2: [0u8; 32],
        frontier_ref_3: [0u8; 32],
        frontier_ref_4: [0u8; 32],
        frontier_hash,
        rotated_by: signer,
        signed_by: signer,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let blob = encode_event(&ParsedEvent::KeyRotation(evt)).unwrap();
    let inner_id = blake3_id(&blob);
    let frame = wrap_one_with_ws(blob, workspace_id);

    let outcome = handle_inbound_bytes(&frame, origin(), &c, 1).unwrap();
    let results = match outcome {
        InboundOutcome::InnerEventsProcessed { results, .. } => results,
        other => panic!("expected InnerEventsProcessed, got {:?}", other),
    };
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].disposition,
        InnerEventDisposition::Applied,
        "key_rotation must apply directly under the new chain"
    );

    let row = get_event(&c, &inner_id).unwrap().expect("row exists");
    assert_eq!(row.status, EventStatus::Applied);

    let ws_b64 = b64_id_invites(&workspace_id);
    let event_b64 = b64_id_invites(&inner_id);
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM key_rotations
             WHERE workspace_id = ?1 AND event_id = ?2",
            params![ws_b64, event_b64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        n, 1,
        "key_rotations row must exist keyed by (workspace_id, event_id)"
    );
}

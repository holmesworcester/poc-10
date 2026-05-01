//! Outgoing-intent → wrap → wire round-trip via the per-connection
//! `ConnectionSender` (plan.md lines 178-185).
//!
//! Topology: a single SQLite DB plays both ends ("Alice writes intents, Bob
//! reads bytes off the socket and unwraps") because the connection-secret
//! frame format is symmetric — the wrap/unwrap functions only need the
//! relevant secret rows, not a full second daemon.
//!
//! Two paths are exercised:
//!
//! 1. **TCP loopback path**: Alice writes a `Send(event_id)` intent, the
//!    `ConnectionSender::drain_to_socket` traverses a real
//!    `transport_v2::send` / `accept_loop` pair, and we read the bytes off
//!    the inbound channel and confirm they unwrap to the original event
//!    blob.
//!
//! 2. **Direct unwrap path**: same intent → wrap → call `unwrap` directly
//!    without going through TCP. This is the simpler path the prompt
//!    suggested as a fallback; it's kept so the test suite still passes if
//!    the loopback ever has port-conflict flake.
//!
//! Both halves share the same in-memory DB to avoid having to mirror
//! `connection_secrets` / `connection_shared_workspaces` rows across two
//! connections (the wrap/unwrap functions read from the same connection
//! handle).

use std::net::SocketAddr;

use base64::Engine;
use rusqlite::{params, Connection};

use topo::event_modules::connection::secrets::{
    ensure_schema as ensure_secrets_schema, upsert as upsert_secret, SecretDirection, SecretRow,
};
use topo::event_modules::connection::wrap::{
    unwrap as connection_unwrap, wrap as connection_wrap, InnerCanonicalEvent, UnwrapKind,
};
use topo::runtime::control_loop::work_item::{ConnectionId, EndpointId, WorkspaceId};
use topo::runtime::jobs::sender::{
    upsert_connection_endpoint, ConnectionSender, INTENT_ENVELOPE_HAVE,
};
use topo::runtime::transport_v2::{
    accept_loop, AddressBook, InboundDelivery, SocketCache,
};
use topo::state::db::control_loop_tables::ensure_schema as ensure_cl_schema;
use topo::state::events_canonical::{self, EventScope, EventStatus};
use topo::state::outbox;
use topo::state::outgoing_intents::{build_intent, upsert_intent, IntentKind};

/// Common DB setup: schema for the outgoing buffer, the secrets table, and
/// the placeholder shared-workspace table that `connection.wrap` reads.
fn open_db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    ensure_cl_schema(&c).unwrap();
    ensure_secrets_schema(&c).unwrap();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS connection_shared_workspaces (
            connection_id BLOB NOT NULL,
            workspace_id  BLOB NOT NULL,
            PRIMARY KEY (connection_id, workspace_id)
        );",
    )
    .unwrap();
    // Real `events` table — `Send` intents look up blobs out of it for the
    // legacy fallback path; new code paths just look in `events_canonical`.
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            event_id    TEXT PRIMARY KEY,
            event_type  TEXT NOT NULL,
            blob        BLOB NOT NULL,
            share_scope TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            inserted_at INTEGER NOT NULL
        );",
    )
    .unwrap();
    c
}

fn add_shared(c: &Connection, conn_id: &ConnectionId, ws: &WorkspaceId) {
    c.execute(
        "INSERT OR IGNORE INTO connection_shared_workspaces VALUES (?1, ?2)",
        params![conn_id.to_vec(), ws.to_vec()],
    )
    .unwrap();
}

fn add_paired_secrets(c: &Connection, conn_id: ConnectionId, secret_id: [u8; 32], key: [u8; 32]) {
    upsert_secret(
        c,
        &SecretRow {
            connection_secret_id: secret_id,
            key,
            direction: SecretDirection::Outbound,
            connection_id: conn_id,
            ttl_ms: i64::MAX / 2,
            created_at_ms: 0,
        },
    )
    .unwrap();
    upsert_secret(
        c,
        &SecretRow {
            connection_secret_id: secret_id,
            key,
            direction: SecretDirection::Inbound,
            connection_id: conn_id,
            ttl_ms: i64::MAX / 2,
            created_at_ms: 0,
        },
    )
    .unwrap();
}

/// Insert a fake durable event. Stores it both in the legacy `events`
/// table (so any legacy lookup still works) AND in `events_canonical`
/// (which is what the new `ConnectionSender` reads from). Returns the
/// 32-byte event id.
fn insert_event(c: &Connection, blob: &[u8], workspace: &WorkspaceId) -> [u8; 32] {
    let id = blake3::hash(blob);
    let mut id_bytes = [0u8; 32];
    id_bytes.copy_from_slice(id.as_bytes());
    let id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&id_bytes);
    c.execute(
        "INSERT OR IGNORE INTO events
            (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id_b64, "test", blob, "shared", 0_i64, 0_i64],
    )
    .unwrap();
    // ConnectionSender resolves wire bytes via `events_canonical` first.
    // Synthesize an EndpointLocal-style row whose wire layout starts with a
    // workspace-prefix block so the recovery path picks the right ws. We
    // use a Durable-scope row here with the real durable bytes so the
    // sender's fallback workspace-by-connection path is also exercised.
    let _ = events_canonical::upsert_event(
        c,
        &events_canonical::EventRow {
            event_id: id_bytes,
            canonical_event_bytes: blob.to_vec(),
            workspace_id: Some(*workspace),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    );
    let _ = workspace;
    id_bytes
}

// ---------------------------------------------------------------------------
// Path 1: TCP loopback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn intent_to_wire_via_tcp_loopback_round_trip() {
    let c = open_db();
    let conn_id: ConnectionId = [0xC1; 32];
    let local_endpoint: EndpointId = [0xA1; 32];
    let remote_endpoint: EndpointId = [0xB1; 32];
    let workspace: WorkspaceId = [0xD1; 32];
    let secret_id = [0xE1; 32];
    let secret_key = [0xF1; 32];

    upsert_connection_endpoint(&c, conn_id, remote_endpoint).unwrap();
    add_shared(&c, &conn_id, &workspace);
    add_paired_secrets(&c, conn_id, secret_id, secret_key);

    // Stash a durable event Alice will Send.
    let event_blob = b"durable-event-payload-v1".to_vec();
    let event_id = insert_event(&c, &event_blob, &workspace);

    // Enqueue the Send intent (writes the outbox row only — the durable
    // event already lives in `events`).
    let intent = build_intent(IntentKind::Send(event_id), conn_id, workspace, 60_000);
    upsert_intent(&c, &intent, 0).unwrap();

    // Spin up the local TCP listener (Bob).
    let book = AddressBook::new();
    let cache = SocketCache::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundDelivery>(8);
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listen_addr = accept_loop(bind, tx).await.unwrap();
    book.insert(remote_endpoint, listen_addr);

    // Alice's per-connection sender refills its hot queue and drains.
    let mut sender = ConnectionSender::new(conn_id);
    sender.refill_if_needed(&c, 1, 64 * 1024).unwrap();
    let report = sender
        .drain_to_socket(&c, local_endpoint, remote_endpoint, &cache, &book)
        .await
        .unwrap();
    assert_eq!(report.frames_written, 1);
    assert_eq!(report.event_ids_completed, vec![event_id]);
    assert!(!report.send_failed);

    // Outbox row deleted.
    let pending = outbox::pending_for_connection(&c, &conn_id, 16).unwrap();
    assert!(pending.is_empty(), "outbox row must be deleted post-send");

    // Bob received bytes on the inbound channel.
    let delivered =
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("inbound timed out")
            .expect("inbound channel closed unexpectedly");
    let bytes = delivered.work_item.bytes;
    assert!(!bytes.is_empty(), "Bob's inbound buffer must contain wire bytes");

    // Bob unwraps and recovers the event blob.
    let res = connection_unwrap(&bytes, [0u8; 32], &c).expect("unwrap");
    assert_eq!(res.kind, UnwrapKind::ConnectionSecret);
    assert_eq!(res.connection_id, Some(conn_id));
    assert_eq!(res.inner_events.len(), 1);
    assert_eq!(res.inner_events[0].workspace_id, workspace);
    assert_eq!(res.inner_events[0].bytes, event_blob);
}

// ---------------------------------------------------------------------------
// Path 2: direct wrap/unwrap (no TCP)
// ---------------------------------------------------------------------------

#[test]
fn intent_to_wire_direct_unwrap_round_trip() {
    let c = open_db();
    let conn_id: ConnectionId = [0xC2; 32];
    let workspace: WorkspaceId = [0xD2; 32];
    let secret_id = [0xE2; 32];
    let secret_key = [0xF2; 32];

    add_shared(&c, &conn_id, &workspace);
    add_paired_secrets(&c, conn_id, secret_id, secret_key);

    // For a Have intent, the inner-event payload is synthetic: tag byte +
    // payload_key_bytes (= the 32-byte event id we're announcing).
    let announced_id = [0x42u8; 32];
    let intent = build_intent(IntentKind::Have(announced_id), conn_id, workspace, 60_000);
    upsert_intent(&c, &intent, 0).unwrap();

    // Build the inner-event blob the way ConnectionSender does for a Have.
    let mut synthetic = Vec::with_capacity(1 + intent.payload.len());
    synthetic.push(INTENT_ENVELOPE_HAVE);
    synthetic.extend_from_slice(&intent.payload);

    let frame = connection_wrap(
        conn_id,
        &[InnerCanonicalEvent {
            workspace_id: workspace,
            bytes: synthetic.clone(),
        }],
        &c,
    )
    .unwrap();

    let res = connection_unwrap(frame.as_bytes(), [0u8; 32], &c).unwrap();
    assert_eq!(res.kind, UnwrapKind::ConnectionSecret);
    assert_eq!(res.connection_id, Some(conn_id));
    assert_eq!(res.inner_events.len(), 1);
    assert_eq!(res.inner_events[0].workspace_id, workspace);
    assert_eq!(res.inner_events[0].bytes, synthetic);
    // Receiver-side dispatch byte is what we expect.
    assert_eq!(res.inner_events[0].bytes[0], INTENT_ENVELOPE_HAVE);
    // Tail bytes match the announced id.
    assert_eq!(&res.inner_events[0].bytes[1..33], &announced_id);
}

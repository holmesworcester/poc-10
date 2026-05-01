//! Per-connection `ConnectionSender` integration tests covering the
//! plan.md lines 178-185 + 211 contract:
//!
//! - the hot queue refills from `outbox` and respects byte budget,
//! - already-present ids are skipped on refill,
//! - frames are written and outbox rows deleted after socket-accept,
//! - send failure leaves outbox rows pending and clears `present`,
//! - **slow-peer isolation**: two senders for two different connections
//!   proceed independently — backpressure on one cannot stall the other.
//!
//! Most invariants are also covered by the in-module unit tests under
//! `runtime::jobs::sender::tests`. This integration suite repeats the
//! happy paths against the public API and adds the two-connection slow-peer
//! scenario that the unit tests don't reach.

use std::net::SocketAddr;

use rusqlite::{params, Connection};

use topo::event_modules::connection::secrets::{
    ensure_schema as ensure_secrets_schema, upsert as upsert_secret, SecretDirection, SecretRow,
};
use topo::runtime::control_loop::work_item::{ConnectionId, EndpointId, WorkspaceId};
use topo::runtime::jobs::sender::{
    upsert_connection_endpoint, ConnectionSender, INTENT_ENVELOPE_HAVE,
};
use topo::runtime::transport_v2::{accept_loop, AddressBook, InboundDelivery, SocketCache};
use topo::state::db::control_loop_tables::ensure_schema as ensure_cl_schema;
use topo::state::events_canonical::{self, EventScope, EventStatus};
use topo::state::outbox;

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
    c
}

fn add_shared(c: &Connection, conn_id: &ConnectionId, ws: &WorkspaceId) {
    c.execute(
        "INSERT OR IGNORE INTO connection_shared_workspaces VALUES (?1, ?2)",
        params![conn_id.to_vec(), ws.to_vec()],
    )
    .unwrap();
}

fn add_outbound_secret(
    c: &Connection,
    conn_id: ConnectionId,
    secret_id: [u8; 32],
    key: [u8; 32],
) {
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
}

/// Synthesize an EndpointLocal `Have` event in `events_canonical` and queue
/// an outbox row for it. `payload_size` lets the test pad the wire blob to
/// inflate the byte estimate so we can probe high-water behavior.
fn enqueue_have(
    c: &Connection,
    conn_id: &ConnectionId,
    ws: &WorkspaceId,
    label: u8,
    queued_at_ms: i64,
    payload_size: usize,
) -> [u8; 32] {
    let mut wire = Vec::with_capacity(1 + 32 + payload_size);
    wire.push(INTENT_ENVELOPE_HAVE);
    wire.extend_from_slice(ws);
    wire.extend(std::iter::repeat(label).take(payload_size));
    let mut h = blake3::Hasher::new();
    h.update(b"hot-queue-test");
    h.update(conn_id);
    h.update(ws);
    h.update(&[label]);
    h.update(&(payload_size as u64).to_le_bytes());
    let mut event_id = [0u8; 32];
    event_id.copy_from_slice(h.finalize().as_bytes());
    events_canonical::upsert_event(
        c,
        &events_canonical::EventRow {
            event_id,
            canonical_event_bytes: wire,
            workspace_id: Some(*ws),
            scope: EventScope::EndpointLocal,
            status: EventStatus::Applied,
            created_at_ms: queued_at_ms,
            expires_at_ms: None,
        },
    )
    .unwrap();
    outbox::enqueue(c, *conn_id, event_id, queued_at_ms).unwrap();
    event_id
}

#[test]
fn refill_respects_high_water_byte_budget() {
    let c = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [10u8; 32];
    add_shared(&c, &conn_id, &ws);

    // Each event is ~1KB on the wire (1 byte tag + 32 byte ws + 1024 padding).
    for i in 0u8..16 {
        enqueue_have(&c, &conn_id, &ws, i, i as i64, 1024);
    }
    let mut sender = ConnectionSender::new(conn_id);
    sender.refill_if_needed(&c, /*low*/ 1, /*high*/ 4 * 1024).unwrap();

    // We should have stopped refilling at or just after 4KB.
    assert!(sender.bytes_in_hot_queue() >= 4 * 1024);
    // And we should have brought in fewer than all 16 (or, at least, a
    // bounded number — at 1KB each we expect about 4-5).
    assert!(sender.hot_queue_len() <= 6, "hot queue must respect byte budget");
}

#[test]
fn refill_skips_already_present_ids() {
    let c = open_db();
    let conn_id: ConnectionId = [1u8; 32];
    let ws: WorkspaceId = [10u8; 32];
    add_shared(&c, &conn_id, &ws);
    let e1 = enqueue_have(&c, &conn_id, &ws, 1, 0, 4);
    let _e2 = enqueue_have(&c, &conn_id, &ws, 2, 1, 4);

    let mut sender = ConnectionSender::new(conn_id);
    sender.refill_if_needed(&c, 1, 64 * 1024).unwrap();
    assert_eq!(sender.hot_queue_len(), 2);
    assert!(sender.contains(&e1));

    // Refill again: nothing new should be added because both ids are in
    // `present`.
    sender.refill_if_needed(&c, 1, 64 * 1024).unwrap();
    assert_eq!(sender.hot_queue_len(), 2);
}

#[tokio::test]
async fn happy_path_writes_and_deletes_outbox_rows() {
    let c = open_db();
    let conn_id: ConnectionId = [0xC1; 32];
    let local: EndpointId = [0xA1; 32];
    let remote: EndpointId = [0xB1; 32];
    let ws: WorkspaceId = [0xD1; 32];
    upsert_connection_endpoint(&c, conn_id, remote).unwrap();
    add_shared(&c, &conn_id, &ws);
    add_outbound_secret(&c, conn_id, [0xE1; 32], [0xF1; 32]);
    let e1 = enqueue_have(&c, &conn_id, &ws, 7, 0, 16);
    let e2 = enqueue_have(&c, &conn_id, &ws, 8, 1, 16);

    let book = AddressBook::new();
    let cache = SocketCache::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundDelivery>(8);
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let local_addr = accept_loop(bind, tx).await.unwrap();
    book.insert(remote, local_addr);

    let mut sender = ConnectionSender::new(conn_id);
    sender.refill_if_needed(&c, 1, 64 * 1024).unwrap();
    let res = sender
        .drain_to_socket(&c, local, remote, &cache, &book)
        .await
        .unwrap();
    assert_eq!(res.frames_written, 1);
    assert!(!res.send_failed);
    assert!(res.event_ids_completed.contains(&e1));
    assert!(res.event_ids_completed.contains(&e2));

    // Outbox is now empty for this connection.
    let pending = outbox::pending_for_connection(&c, &conn_id, 16).unwrap();
    assert!(pending.is_empty());

    // Frame arrived on the receiver.
    let _delivered = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn send_failure_leaves_outbox_pending_and_clears_present() {
    // No outbound secret -> wrap fails on first batch.
    let c = open_db();
    let conn_id: ConnectionId = [0xC2; 32];
    let local: EndpointId = [0xA2; 32];
    let remote: EndpointId = [0xB2; 32];
    let ws: WorkspaceId = [0xD2; 32];
    upsert_connection_endpoint(&c, conn_id, remote).unwrap();
    add_shared(&c, &conn_id, &ws);
    // intentionally no outbound secret
    let e1 = enqueue_have(&c, &conn_id, &ws, 1, 0, 4);

    let book = AddressBook::new();
    let cache = SocketCache::new();
    let mut sender = ConnectionSender::new(conn_id);
    sender.refill_if_needed(&c, 1, 64 * 1024).unwrap();
    assert!(sender.contains(&e1));
    let res = sender
        .drain_to_socket(&c, local, remote, &cache, &book)
        .await
        .unwrap();
    assert_eq!(res.frames_written, 0);
    assert!(res.send_failed);
    assert!(!sender.contains(&e1), "present must be cleared on send failure");
    let pending = outbox::pending_for_connection(&c, &conn_id, 16).unwrap();
    assert_eq!(pending.len(), 1, "outbox row must stay pending on failure");
    assert_eq!(pending[0].0, e1);
}

#[tokio::test]
async fn two_senders_proceed_independently_under_slow_peer() {
    // plan.md line 211: each connection has its own ConnectionSender; a
    // slow peer fills only its own hot queue. Here connection B has no
    // outbound secret so its sender always fails wrap; connection A is
    // healthy. We assert A successfully drains while B's failure does not
    // affect A — they share no in-memory state.
    let c = open_db();
    let conn_a: ConnectionId = [0xA0; 32];
    let conn_b: ConnectionId = [0xB0; 32];
    let local: EndpointId = [0x01; 32];
    let remote_a: EndpointId = [0x02; 32];
    let remote_b: EndpointId = [0x03; 32];
    let ws_a: WorkspaceId = [0x10; 32];
    let ws_b: WorkspaceId = [0x11; 32];

    upsert_connection_endpoint(&c, conn_a, remote_a).unwrap();
    upsert_connection_endpoint(&c, conn_b, remote_b).unwrap();
    add_shared(&c, &conn_a, &ws_a);
    add_shared(&c, &conn_b, &ws_b);
    // Healthy connection A only gets an outbound secret.
    add_outbound_secret(&c, conn_a, [0xE0; 32], [0xF0; 32]);
    // (no secret for B — every wrap will fail with NoOutboundSecret)

    let e_a = enqueue_have(&c, &conn_a, &ws_a, 1, 0, 4);
    let e_b = enqueue_have(&c, &conn_b, &ws_b, 2, 0, 4);

    // A real listener for A, *no* listener for B. We want B's failure mode
    // to be wrap-stage (NoOutboundSecret) so the test is deterministic;
    // routing it to a non-existent address would also fail but at the
    // transport stage, which is fine but slower.
    let book = AddressBook::new();
    let cache = SocketCache::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundDelivery>(8);
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let local_addr = accept_loop(bind, tx).await.unwrap();
    book.insert(remote_a, local_addr);

    let mut sender_a = ConnectionSender::new(conn_a);
    let mut sender_b = ConnectionSender::new(conn_b);
    sender_a.refill_if_needed(&c, 1, 64 * 1024).unwrap();
    sender_b.refill_if_needed(&c, 1, 64 * 1024).unwrap();

    // Drain B first — this should fail. The failure must NOT touch A.
    let res_b = sender_b
        .drain_to_socket(&c, local, remote_b, &cache, &book)
        .await
        .unwrap();
    assert!(res_b.send_failed, "B has no secret; wrap must fail");
    assert_eq!(res_b.frames_written, 0);
    // B's outbox row is still pending.
    let pending_b = outbox::pending_for_connection(&c, &conn_b, 16).unwrap();
    assert_eq!(pending_b.len(), 1);
    assert_eq!(pending_b[0].0, e_b);

    // A's drain proceeds successfully — independent state, independent
    // wrap key, independent socket.
    let res_a = sender_a
        .drain_to_socket(&c, local, remote_a, &cache, &book)
        .await
        .unwrap();
    assert_eq!(res_a.frames_written, 1);
    assert!(!res_a.send_failed);
    assert!(res_a.event_ids_completed.contains(&e_a));

    // A's outbox is drained.
    let pending_a = outbox::pending_for_connection(&c, &conn_a, 16).unwrap();
    assert!(pending_a.is_empty(), "A drained successfully");
    // B's outbox is still pending — slow peer holds only its own backlog.
    let pending_b = outbox::pending_for_connection(&c, &conn_b, 16).unwrap();
    assert_eq!(pending_b.len(), 1);

    // Bytes arrived for A.
    let _delivered =
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

    // Cross-isolation: A's `present` does not contain B's id and vice versa.
    assert!(!sender_a.contains(&e_b));
    assert!(!sender_b.contains(&e_a));
}

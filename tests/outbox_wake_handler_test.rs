//! Integration tests for the real `WorkItem::OutboxWake` handler
//! (audit round 4).
//!
//! Two scenarios:
//!
//! 1. **Happy path**: enqueue two outbox rows, install an
//!    `OutboxWakeContext`, fire one `OutboxWake(C)` work item through the
//!    dispatcher. Both events should be wrapped, written to the socket
//!    (via a mock `accept_loop`), and the outbox rows deleted.
//!
//! 2. **Send-failure backoff**: same setup but with no outbound secret.
//!    The drain reports `send_failed = true` and the handler should
//!    schedule a follow-up `OutboxWake` via `StepResult.queue_writes`,
//!    leaving the outbox row pending.

use std::net::SocketAddr;
use std::sync::Arc;

use rusqlite::{params, Connection};

use topo::event_modules::connection::secrets::{
    ensure_schema as ensure_secrets_schema, upsert as upsert_secret, SecretDirection, SecretRow,
};
use topo::runtime::control_loop::{
    dispatch_step, register_default_handlers, ModuleRegistry, OutboxWakeContext, StepContext,
};
use topo::runtime::control_loop::work_item::{
    ConnectionId, EndpointId, OutboxWake, WorkItem, WorkItemKind, WorkspaceId,
};
use topo::runtime::jobs::sender::{
    upsert_connection_endpoint, INTENT_ENVELOPE_HAVE,
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

fn add_outbound_secret(c: &Connection, conn_id: ConnectionId, secret_id: [u8; 32], key: [u8; 32]) {
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

/// Insert an EndpointLocal Have event in `events_canonical` and queue
/// an outbox row for it. Returns the synthesized event id.
fn enqueue_have(
    c: &Connection,
    conn_id: &ConnectionId,
    ws: &WorkspaceId,
    label: u8,
    queued_at_ms: i64,
) -> [u8; 32] {
    let mut wire = Vec::with_capacity(1 + 32 + 32);
    wire.push(INTENT_ENVELOPE_HAVE);
    wire.extend_from_slice(ws);
    wire.extend_from_slice(&[label; 32]);
    let mut h = blake3::Hasher::new();
    h.update(b"outbox-wake-test");
    h.update(conn_id);
    h.update(ws);
    h.update(&[label]);
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

/// We share one global `OutboxWakeContext` across tests because
/// `OnceLock::set` rejects re-installs. The context's local endpoint id
/// is universal; per-test routing differences are expressed by inserting
/// entries on the shared `AddressBook` keyed by per-test endpoint ids.
///
/// We do NOT pin a tokio runtime handle on the shared context — each
/// test runs on its own runtime, so the handler falls back to
/// `Handle::try_current()` from inside the test future.
fn install_or_get_ctx() -> Arc<OutboxWakeContext> {
    if let Some(ctx) = OutboxWakeContext::current() {
        return ctx;
    }
    let ctx = Arc::new(OutboxWakeContext {
        local_endpoint_id: [0xAA; 32],
        socket_cache: Arc::new(SocketCache::new()),
        address_book: Arc::new(AddressBook::new()),
        runtime_handle: None,
    });
    let _ = ctx.clone().install();
    OutboxWakeContext::current().expect("ctx installed")
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_wake_drains_outbox_through_dispatcher() {
    let c = open_db();
    // Use distinct connection + endpoint ids per test so the shared
    // OutboxWakeContext's address book / socket cache don't collide.
    let conn_id: ConnectionId = [0x11; 32];
    let remote: EndpointId = [0x22; 32];
    let ws: WorkspaceId = [0x33; 32];
    upsert_connection_endpoint(&c, conn_id, remote).unwrap();
    add_shared(&c, &conn_id, &ws);
    add_outbound_secret(&c, conn_id, [0xE1; 32], [0xF1; 32]);

    let e1 = enqueue_have(&c, &conn_id, &ws, 1, 0);
    let e2 = enqueue_have(&c, &conn_id, &ws, 2, 1);

    // Stand up a real TCP listener on the receiver side.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundDelivery>(8);
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let local_addr = accept_loop(bind, tx).await.unwrap();

    let ctx = install_or_get_ctx();
    ctx.address_book.insert(remote, local_addr);

    // Wire the dispatcher.
    let mut reg = ModuleRegistry::new();
    register_default_handlers(&mut reg);
    let item = WorkItem::OutboxWake(OutboxWake { connection_id: conn_id });
    let step_ctx = StepContext {
        conn: &c,
        now_ms: 100,
        worker_id: "test-worker",
    };

    let res = dispatch_step(&reg, &item, &step_ctx).expect("dispatch ok");
    // Happy path: no retry queued.
    assert!(
        res.queue_writes.is_empty(),
        "expected no retry, got {:?}",
        res.queue_writes
    );

    // Both outbox rows deleted.
    let pending = outbox::pending_for_connection(&c, &conn_id, 16).unwrap();
    assert!(
        pending.is_empty(),
        "outbox should be empty after happy-path drain, got {:?}",
        pending
    );

    // The receiver side actually got bytes.
    let _delivered = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .expect("inbound bytes arrived");

    // Sanity: the event ids were the ones we enqueued.
    assert_ne!(e1, e2);
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_wake_schedules_retry_on_send_failure() {
    let c = open_db();
    // Distinct ids so the shared address book doesn't see the receiver
    // we set up in the happy-path test.
    let conn_id: ConnectionId = [0x44; 32];
    let remote: EndpointId = [0x55; 32];
    let ws: WorkspaceId = [0x66; 32];
    upsert_connection_endpoint(&c, conn_id, remote).unwrap();
    add_shared(&c, &conn_id, &ws);
    // Intentionally no outbound secret -> wrap fails.

    let e1 = enqueue_have(&c, &conn_id, &ws, 9, 0);

    let _ctx = install_or_get_ctx();

    let mut reg = ModuleRegistry::new();
    register_default_handlers(&mut reg);
    let item = WorkItem::OutboxWake(OutboxWake { connection_id: conn_id });
    let step_ctx = StepContext {
        conn: &c,
        now_ms: 100,
        worker_id: "test-worker",
    };

    let res = dispatch_step(&reg, &item, &step_ctx).expect("dispatch ok");

    // Retry must be queued (a new OutboxWake for the same connection).
    assert_eq!(res.queue_writes.items.len(), 1, "expected one retry queued");
    let retry = &res.queue_writes.items[0];
    assert_eq!(retry.kind(), WorkItemKind::OutboxWake);
    match retry {
        WorkItem::OutboxWake(w) => assert_eq!(w.connection_id, conn_id),
        _ => panic!("expected OutboxWake retry"),
    }

    // Outbox row stays pending (sender did not delete it on failure).
    let pending = outbox::pending_for_connection(&c, &conn_id, 16).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, e1);
}

//! Integration tests for the new `ControlLoopRuntime` owner.
//!
//! Three scenarios:
//!
//! 1. `runtime_starts_and_shuts_down_cleanly` — start, immediately
//!    shutdown. Asserts clean exit with no panics or hung tasks.
//!
//! 2. `runtime_processes_inbound_frame_end_to_end` — start runtime, send
//!    a real `wrap_bootstrap`-wrapped TenantEvent over TCP loopback,
//!    assert the inbound chain runs end-to-end and the
//!    `events_canonical` row reaches `applied`.
//!
//! 3. `runtime_drains_outbox_to_peer` — start two runtimes (A and B),
//!    pre-load A with a connection secret + outbox row pointing at B's
//!    listener, then assert B's `inbound_bytes` table records the
//!    delivered frame within a timeout. This exercises the FULL new
//!    path: outbox_wake_worker → OutboxWake handler → ConnectionSender
//!    → wrap → transport_v2 send → B's transport_bridge → inbound chain.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use rusqlite::params;

use topo::event_modules::connection::secrets::{
    upsert as upsert_secret, SecretDirection, SecretRow,
};
use topo::event_modules::connection::wrap::{wrap_bootstrap, InnerCanonicalEvent};
use topo::event_modules::{encode_event, ParsedEvent, TenantEvent, WorkspaceEvent};
use topo::runtime::control_loop::work_item::{
    BlakeId, ConnectionId, EndpointId, WorkspaceId,
};
use topo::runtime::control_loop::ControlLoopRuntime;
use topo::runtime::jobs::sender::upsert_connection_endpoint;
use topo::runtime::transport_v2::{send as transport_send, AddressBook, SocketCache};
use topo::state::events_canonical::{self, EventRow, EventScope, EventStatus};
use topo::state::outbox;

const SENDER_ENDPOINT: EndpointId = [11u8; 32];
const RECIPIENT_ENDPOINT: EndpointId = [22u8; 32];

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn tenant_blob(marker: u8) -> Vec<u8> {
    let e = TenantEvent {
        created_at_ms: 1_000 + marker as u64,
        public_key: [marker; 32],
    };
    encode_event(&ParsedEvent::Tenant(e)).unwrap()
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_starts_and_shuts_down_cleanly() {
    let dir = tmpdir();
    let db_path = dir.path().join("control_loop.db");
    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();

    let handles = ControlLoopRuntime::start(bind, RECIPIENT_ENDPOINT, &db_path)
        .await
        .expect("runtime start");

    // Give the workers a chance to enter their idle backoff so we
    // exercise the shutdown path on a steady-state runtime.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // Shutdown must complete within a generous timeout.
    let shutdown_res =
        tokio::time::timeout(Duration::from_secs(5), ControlLoopRuntime::shutdown(handles))
            .await
            .expect("shutdown did not hang");
    shutdown_res.expect("shutdown returned ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_processes_inbound_frame_end_to_end() {
    // Receiver side: start a runtime owning the listener + bridge.
    let dir = tmpdir();
    let db_path = dir.path().join("control_loop.db");
    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();

    let handles = ControlLoopRuntime::start(bind, RECIPIENT_ENDPOINT, &db_path)
        .await
        .expect("runtime start");
    let recipient_addr = handles.runtime.listen_addr;
    let recipient_db = handles.runtime.db.clone();

    // The TenantEvent projector's `tenants` table is now installed by
    // `ensure_infra_schema` via the registry-driven `ensure_all_module_schemas`
    // pass, so no manual `tenant::ensure_schema` is needed here. (See
    // plan.md "State and Registry", lines 124-176.)

    // Build a real OutboundFrame via wrap_bootstrap carrying a single
    // self-contained TenantEvent (mirrors transport_to_inbound_chain).
    let blob = tenant_blob(0xCA);
    let inner_event_id = blake3_id(&blob);
    let inner = vec![InnerCanonicalEvent {
        workspace_id: [0u8; 32],
        bytes: blob,
    }];
    let frame = wrap_bootstrap(SENDER_ENDPOINT, RECIPIENT_ENDPOINT, &inner)
        .expect("wrap_bootstrap");

    // Sender side: vanilla transport_v2 send.
    let book = AddressBook::new();
    book.insert(RECIPIENT_ENDPOINT, recipient_addr);
    let cache = SocketCache::new();
    transport_send(&cache, &book, SENDER_ENDPOINT, RECIPIENT_ENDPOINT, frame)
        .await
        .expect("transport_send");

    // Poll until the inner event applies on the receiver. Bound the
    // wait so a regression doesn't hang the test.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut applied = false;
    while std::time::Instant::now() < deadline {
        {
            let g = recipient_db.lock().await;
            if let Some(row) = events_canonical::get(&g, &inner_event_id).unwrap() {
                if row.status == EventStatus::Applied {
                    applied = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if !applied {
        let g = recipient_db.lock().await;
        let n_inbound: i64 = g
            .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0))
            .unwrap();
        let n_events: i64 = g
            .query_row("SELECT COUNT(*) FROM events_canonical", [], |r| r.get(0))
            .unwrap();
        drop(g);
        let _ = ControlLoopRuntime::shutdown(handles).await;
        panic!(
            "timed out: inbound_bytes={}, events_canonical={}",
            n_inbound, n_events
        );
    }

    // Clean up.
    ControlLoopRuntime::shutdown(handles)
        .await
        .expect("shutdown ok");
}

/// Plan.md Stage 2: a Workspace event flows through the full new
/// chain (TCP → bridge → handle_inbound_bytes → unwrap → admit →
/// parse → context → project → apply) and lands in the `workspaces`
/// projection table keyed by `(workspace_id, event_id)`. Mirrors
/// `runtime_processes_inbound_frame_end_to_end` but uses a Workspace
/// event instead of a Tenant event, exercising the new
/// generic-context-loader-driven workspace projector that derives
/// `workspace_id` directly from the event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_processes_workspace_event_via_new_chain() {
    let dir = tmpdir();
    let db_path = dir.path().join("control_loop.db");
    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();

    let handles = ControlLoopRuntime::start(bind, RECIPIENT_ENDPOINT, &db_path)
        .await
        .expect("runtime start");
    let recipient_addr = handles.runtime.listen_addr;
    let recipient_db = handles.runtime.db.clone();

    // Build a Workspace event with workspace_id set to the same value
    // as public_key (the canonical convention for root events).
    let workspace_pub: [u8; 32] = [0x77; 32];
    let ws = WorkspaceEvent {
        created_at_ms: 9_876,
        workspace_id: workspace_pub,
        public_key: workspace_pub,
        name: "runtime-ws".to_string(),
    };
    let blob = encode_event(&ParsedEvent::Workspace(ws)).unwrap();
    let inner_event_id = blake3_id(&blob);
    let inner = vec![InnerCanonicalEvent {
        workspace_id: workspace_pub,
        bytes: blob,
    }];
    let frame = wrap_bootstrap(SENDER_ENDPOINT, RECIPIENT_ENDPOINT, &inner)
        .expect("wrap_bootstrap");

    let book = AddressBook::new();
    book.insert(RECIPIENT_ENDPOINT, recipient_addr);
    let cache = SocketCache::new();
    transport_send(&cache, &book, SENDER_ENDPOINT, RECIPIENT_ENDPOINT, frame)
        .await
        .expect("transport_send");

    // Poll until the workspace event applies on the receiver.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut applied = false;
    while std::time::Instant::now() < deadline {
        {
            let g = recipient_db.lock().await;
            if let Some(row) = events_canonical::get(&g, &inner_event_id).unwrap() {
                if row.status == EventStatus::Applied {
                    applied = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if !applied {
        let g = recipient_db.lock().await;
        let n_inbound: i64 = g
            .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0))
            .unwrap();
        let n_events: i64 = g
            .query_row("SELECT COUNT(*) FROM events_canonical", [], |r| r.get(0))
            .unwrap();
        drop(g);
        let _ = ControlLoopRuntime::shutdown(handles).await;
        panic!(
            "timed out: inbound_bytes={}, events_canonical={}",
            n_inbound, n_events
        );
    }

    // Assert the projection row landed keyed by `(workspace_id,
    // event_id)`. For a root workspace event, the projection's
    // `workspace_id` IS the event_id (children reference the root
    // via this same id).
    {
        use base64::Engine;
        let g = recipient_db.lock().await;
        let event_id_b64 = base64::engine::general_purpose::STANDARD.encode(inner_event_id);
        let n: i64 = g
            .query_row(
                "SELECT COUNT(*) FROM workspaces
                 WHERE workspace_id = ?1 AND event_id = ?2",
                rusqlite::params![event_id_b64, event_id_b64],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            n, 1,
            "workspaces row must exist keyed by (workspace_id == event_id, event_id)"
        );
    }

    ControlLoopRuntime::shutdown(handles)
        .await
        .expect("shutdown ok");
}

/// End-to-end drain: writes an outbox row on A, the runtime's
/// `outbox_wake_worker` picks it up, the OutboxWake handler wraps via
/// the connection secret and sends to B's listener, and B's transport
/// bridge unwraps + applies. This is the FULL new path with no
/// runtime/peering involvement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runtime_drains_outbox_to_peer() {
    // ---- B (receiver) ----
    let dir_b = tmpdir();
    let db_b_path = dir_b.path().join("control_loop_b.db");
    // Use distinct endpoint ids per test so a process-shared
    // OutboxWakeContext (OnceLock) can't collide across runs.
    let endpoint_b: EndpointId = [0xB1; 32];
    let bind_b: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let handles_b = ControlLoopRuntime::start(bind_b, endpoint_b, &db_b_path)
        .await
        .expect("B start");
    let addr_b = handles_b.runtime.listen_addr;
    let db_b = handles_b.runtime.db.clone();

    // ---- A (sender) ----
    let dir_a = tmpdir();
    let db_a_path = dir_a.path().join("control_loop_a.db");
    let endpoint_a: EndpointId = [0xA1; 32];
    let bind_a: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let handles_a = ControlLoopRuntime::start(bind_a, endpoint_a, &db_a_path)
        .await
        .expect("A start");
    let db_a = handles_a.runtime.db.clone();
    // `tenants` (and every other event-module table) is installed by
    // `ensure_infra_schema` through the registry-driven schema pass; no
    // manual `tenant::ensure_schema` required after `ControlLoopRuntime::start`.

    // The OutboxWakeContext is process-shared via a OnceLock. Whichever
    // runtime installed it first won the slot; we look it up and seed
    // it with B's address so A's OutboxWake handler can dial. (Both
    // runtimes share one `address_book`; that's fine because it's
    // keyed on `endpoint_id`.)
    let ctx = topo::runtime::control_loop::OutboxWakeContext::current()
        .expect("OutboxWakeContext was installed by ControlLoopRuntime::start");
    ctx.address_book.insert(endpoint_b, addr_b);

    // Pre-load A's DB with the routing the OutboxWake handler needs:
    //   1. connection_endpoints(conn_id -> endpoint_b) so the handler
    //      knows where to send.
    //   2. connection_shared_workspaces(conn_id -> ws) so wrap()'s
    //      workspace check passes.
    //   3. An OUTBOUND secret on A keyed by (conn_id, secret_id).
    //   4. The applied event row (the outbox carries the id; the
    //      sender resolves the bytes from events_canonical).
    //   5. The outbox row itself.
    let conn_id: ConnectionId = [0xC1; 32];
    let workspace_id: WorkspaceId = [0xD1; 32];
    let secret_id: [u8; 32] = [0xE1; 32];
    let secret_key: [u8; 32] = [0xF1; 32];
    {
        let g = db_a.lock().await;
        upsert_connection_endpoint(&g, conn_id, endpoint_b).unwrap();
        // connection_shared_workspaces is created on demand by
        // connection.wrap if missing; insert explicitly to avoid
        // depending on that side effect.
        g.execute_batch(
            "CREATE TABLE IF NOT EXISTS connection_shared_workspaces (
                connection_id BLOB NOT NULL,
                workspace_id  BLOB NOT NULL,
                PRIMARY KEY (connection_id, workspace_id)
            );",
        )
        .unwrap();
        g.execute(
            "INSERT OR IGNORE INTO connection_shared_workspaces VALUES (?1, ?2)",
            params![conn_id.to_vec(), workspace_id.to_vec()],
        )
        .unwrap();
        upsert_secret(
            &g,
            &SecretRow {
                connection_secret_id: secret_id,
                key: secret_key,
                direction: SecretDirection::Outbound,
                connection_id: conn_id,
                ttl_ms: i64::MAX / 2,
                created_at_ms: 0,
            },
        )
        .unwrap();

        // Build a tenant event whose canonical bytes carry the workspace
        // id we declared shared. The TenantEvent codec doesn't actually
        // bind to a workspace, but the sender's
        // `connection.wrap` invocation will pass `workspace_id` into the
        // InnerCanonicalEvent envelope explicitly — see
        // `runtime/jobs/sender::build_inner_envelope`. The id we store
        // here must match one of the workspace_id columns for the
        // wrap() shared check.
        // For the sender path the canonical_event_bytes get sent
        // verbatim; the assertion on B is that the bytes arrive in the
        // inbound_bytes table (we do not require the inner type to
        // resolve to a workspace projector — TenantEvent suffices and
        // the chain is permissive).
        let blob = tenant_blob(0xAB);
        let event_id = blake3_id(&blob);
        events_canonical::upsert_event(
            &g,
            &EventRow {
                event_id,
                canonical_event_bytes: blob,
                workspace_id: Some(workspace_id),
                scope: EventScope::Durable,
                status: EventStatus::Applied,
                created_at_ms: 0,
                expires_at_ms: None,
            },
        )
        .unwrap();
        outbox::enqueue(&g, conn_id, event_id, 0).unwrap();
    }

    // ---- B's INBOUND secret keyed by the same secret_id ----
    {
        let g = db_b.lock().await;
        upsert_secret(
            &g,
            &SecretRow {
                connection_secret_id: secret_id,
                key: secret_key,
                direction: SecretDirection::Inbound,
                connection_id: conn_id,
                ttl_ms: i64::MAX / 2,
                created_at_ms: 0,
            },
        )
        .unwrap();
        // shared_workspaces also required on B for the unwrap-side
        // workspace filter.
        g.execute_batch(
            "CREATE TABLE IF NOT EXISTS connection_shared_workspaces (
                connection_id BLOB NOT NULL,
                workspace_id  BLOB NOT NULL,
                PRIMARY KEY (connection_id, workspace_id)
            );",
        )
        .unwrap();
        g.execute(
            "INSERT OR IGNORE INTO connection_shared_workspaces VALUES (?1, ?2)",
            params![conn_id.to_vec(), workspace_id.to_vec()],
        )
        .unwrap();
    }

    // Poll B's `inbound_bytes` until at least one row with a non-empty
    // payload arrives. This is the substrate-level proof-of-delivery —
    // B's bridge wrote the row before running the chain.
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let mut delivered = false;
    while std::time::Instant::now() < deadline {
        {
            let g = db_b.lock().await;
            let n_inbound: i64 = g
                .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0))
                .unwrap_or(0);
            if n_inbound > 0 {
                delivered = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut diag_a = String::new();
    let mut diag_b = String::new();
    if !delivered {
        let g_a = db_a.lock().await;
        let outbox_count: i64 = g_a
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
            .unwrap_or(-1);
        diag_a = format!("A.outbox={}", outbox_count);
        drop(g_a);
        let g_b = db_b.lock().await;
        let inbound_count: i64 = g_b
            .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0))
            .unwrap_or(-1);
        diag_b = format!("B.inbound_bytes={}", inbound_count);
        drop(g_b);
    }

    // Tear down regardless of outcome (so the workers don't outlive the test).
    let _ = ControlLoopRuntime::shutdown(handles_a).await;
    let _ = ControlLoopRuntime::shutdown(handles_b).await;

    assert!(
        delivered,
        "no inbound bytes arrived at B within deadline: {} {}",
        diag_a, diag_b
    );
}

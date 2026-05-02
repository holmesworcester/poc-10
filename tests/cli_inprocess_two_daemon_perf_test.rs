//! # Two-daemon REAL chain throughput perf test (in-process)
//!
//! Boots two `ControlLoopRuntime` instances in one process (each with
//! its own DB + dispatcher + per-connection sender actors) over TCP
//! loopback, performs the REAL `EstablishConnection` bootstrap via
//! `api::run`, then authors N messages via the public
//! `api::run(SendMessage)` surface and waits for daemon B's
//! `messages` projection to converge.
//!
//! Why this is different from the existing perf tests:
//!
//! - `cli_blackbox_two_daemon_perf_test.rs` spawns `topo` as a
//!   subprocess for each `send` — its number is dominated by process
//!   spawn + DB-open overhead, not chain throughput.
//! - `perf_new_chain_test.rs` synthesizes events directly into A's
//!   `events_canonical` with `status=Applied`, skipping admit / parse
//!   / context / project / apply on the producer AND skipping the
//!   sync compare/have/need round-trip on the wire.
//!
//! This test exercises the FULL chain on both sides: A authors via
//! `api::run`, the dispatcher applies the message, the outbox row
//! gets enqueued (post-apply hook), the per-connection sender wraps
//! and sends, and B's dispatcher runs admit → parse → context →
//! project → apply for the real Message event.
//!
//! ## Known limitation (in-process bootstrap)
//!
//! The current `EstablishConnection` flow reads a `.<db>.listen` file
//! beside the DB to embed the local listen address in the bootstrap
//! envelope. This test writes that file before submitting
//! `EstablishConnection`. After the Connection event applies on both
//! sides, the per-event sync compare/have/need flow drives message
//! propagation. With parallel agent #64 in flight on the sync layer
//! the convergence path may stall for some N ranges; the substrate
//! tests above (`inbound_chain_test`, `daemon_minimal_test`) plus
//! `perf_new_chain_test` (which pre-seeds connection state and
//! synthesizes events) remain the dispatcher's authoritative
//! benchmarks.
//!
//! ## Invocation
//!
//! Tests are `#[ignore]`'d. Invoke explicitly with
//! `cargo test --release --test cli_inprocess_two_daemon_perf_test
//!  -- --ignored --nocapture`.

use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use topo::api::{self, Command, CommandOutcome, DbHandle, EndpointId};
use topo::runtime::control_loop::ControlLoopRuntime;

/// Process-wide test serializer. The OutboxWakeContext + sender map are
/// process-wide OnceLocks; running these tests in parallel within the
/// same binary cross-pollutes their address books and senders, so we
/// hold this Mutex for the duration of a test body.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Paste the listen-addr file beside the DB file. The
/// `EstablishConnection` submit path reads this file to embed the
/// daemon's own address into the bootstrap envelope, so the responder
/// can dial back the daemon (not the ephemeral CLI socket).
fn write_listen_addr_file(db_path: &Path, addr: SocketAddr) {
    let mut p = db_path.to_path_buf();
    let stem = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "topo.db".to_string());
    p.set_file_name(format!(".{}.listen", stem));
    std::fs::write(&p, addr.to_string()).expect("write listen file");
}

struct Daemon {
    handles: topo::runtime::control_loop::ControlLoopHandles,
    endpoint_id: EndpointId,
    listen_addr: SocketAddr,
}

async fn boot_daemon(db_path: &Path) -> Daemon {
    let signing_key = api::ensure_signing_key(db_path).expect("ensure_signing_key");
    let endpoint_id = signing_key.verifying_key().to_bytes();
    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let handles = ControlLoopRuntime::start(bind, endpoint_id, db_path)
        .await
        .expect("runtime start");
    let listen_addr = handles.runtime.listen_addr;
    write_listen_addr_file(db_path, listen_addr);

    // Mirror the production daemon's address-book seeding so a sibling
    // runtime in the same process can resolve the listen addr.
    if let Some(ctx) = topo::runtime::control_loop::default_handlers::OutboxWakeContext::current() {
        ctx.address_book.attach_db_path(db_path.to_path_buf());
        ctx.address_book.insert(endpoint_id, listen_addr);
        ctx.address_book.warm_from_db();
    }

    Daemon {
        handles,
        endpoint_id,
        listen_addr,
    }
}

/// Wait until B has at least `n` messages in `workspace_id` (in B's
/// `messages` projection). The workspace event itself isn't necessarily
/// in B's `workspaces` projection — only the Connection event was
/// bootstrap-wrapped — so we count rows in the `messages` table
/// directly. This goes through the runtime's shared connection so we
/// don't need a second handle.
async fn wait_for_messages_on_b(
    db_b_arc: &std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    workspace_id: &[u8; 32],
    n: usize,
    timeout: Duration,
) -> Result<f64, (usize, f64)> {
    use base64::Engine;
    let ws_b64 = base64::engine::general_purpose::STANDARD.encode(workspace_id);
    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut last_count: usize = 0;
    loop {
        let elapsed = start.elapsed();
        let count: usize = {
            let g = db_b_arc.lock().await;
            g.query_row(
                "SELECT COUNT(*) FROM messages WHERE workspace_id = ?1",
                rusqlite::params![ws_b64],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize
        };
        if count >= n {
            return Ok(elapsed.as_secs_f64());
        }
        if elapsed >= timeout {
            return Err((count, elapsed.as_secs_f64()));
        }
        if last_report.elapsed() >= Duration::from_secs(2) {
            let delta = count.saturating_sub(last_count);
            eprintln!(
                "[+{:.1}s] B msgs: {}/{} (delta: +{})",
                elapsed.as_secs_f64(),
                count,
                n,
                delta,
            );
            last_count = count;
            last_report = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn run_inprocess_perf(n: usize, timeout: Duration) {
    // Serialize across tests in this binary — see TEST_LOCK doc.
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let db_a = dir_a.path().join("a.db");
    let db_b = dir_b.path().join("b.db");
    // Leak so DBs survive any panic for postmortem.
    std::mem::forget(dir_a);
    std::mem::forget(dir_b);

    eprintln!("[boot] db_a = {}", db_a.display());
    eprintln!("[boot] db_b = {}", db_b.display());

    let a = boot_daemon(&db_a).await;
    let b = boot_daemon(&db_b).await;
    eprintln!(
        "[boot] A: ep={} addr={}",
        hex8(&a.endpoint_id),
        a.listen_addr
    );
    eprintln!(
        "[boot] B: ep={} addr={}",
        hex8(&b.endpoint_id),
        b.listen_addr
    );

    // Cross-seed addresses on both runtimes' shared OutboxWakeContext
    // (they share one OnceLock-installed context).
    if let Some(ctx) = topo::runtime::control_loop::default_handlers::OutboxWakeContext::current() {
        ctx.address_book.insert(a.endpoint_id, a.listen_addr);
        ctx.address_book.insert(b.endpoint_id, b.listen_addr);
    }

    let db_a_handle = DbHandle::from_runtime(&a.handles);
    let db_b_handle = DbHandle::from_runtime(&b.handles);

    // 1. Create a workspace on A.
    let create_outcome = api::run(
        &db_a_handle,
        Command::CreateWorkspace {
            name: "perf-ws".to_string(),
        },
        Duration::from_secs(10),
    )
    .await
    .expect("create_workspace");
    assert!(matches!(create_outcome, CommandOutcome::Applied));
    let workspaces = api::list_workspaces(&db_a_handle)
        .await
        .expect("list_workspaces");
    let ws = workspaces.last().cloned().expect("workspace applied");
    eprintln!("[boot] workspace applied on A: {}", hex8(&ws.id));

    // 2. Real bootstrap: encode the invite, submit EstablishConnection
    //    on B (B initiates so A receives the bootstrap frame).
    let invite_blob =
        api::encode_connection_invite(&a.endpoint_id, a.listen_addr, &ws.id);
    let connect_start = Instant::now();
    let connect_outcome = api::run(
        &db_b_handle,
        Command::EstablishConnection {
            invite_blob: invite_blob.clone(),
        },
        Duration::from_secs(20),
    )
    .await
    .expect("EstablishConnection on B");
    assert!(
        matches!(connect_outcome, CommandOutcome::Applied),
        "EstablishConnection must apply on B (got {:?})",
        connect_outcome
    );
    eprintln!(
        "[boot] EstablishConnection applied on B in {:.2}s",
        connect_start.elapsed().as_secs_f64()
    );

    // Wait until the same Connection event has applied on A as well —
    // post_apply on A creates the connection_secrets / endpoints rows
    // the sender actor needs.
    let conn_a_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < conn_a_deadline {
        let st = api::endpoint_status(&db_a_handle).await.expect("status A");
        if st.events_applied >= 2 {
            // workspace + connection
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let st_a = api::endpoint_status(&db_a_handle).await.unwrap();
    eprintln!(
        "[boot] A status: applied={} blocked={} pending={}",
        st_a.events_applied, st_a.events_blocked, st_a.events_pending
    );

    // 3. Author N messages via api::run on A. Pipeline by spawning
    //    `submit` futures and only awaiting their completion at the
    //    end — `api::run` polls every 20ms internally so doing them
    //    serially would hit a 50/s ceiling unrelated to the chain.
    let send_start = Instant::now();
    let db_a_arc = Arc::new(db_a_handle);
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let dba = db_a_arc.clone();
        let ws_id = ws.id;
        let content = format!("perf-{}", i);
        let h = tokio::spawn(async move {
            let cmd = Command::SendMessage {
                workspace_id: ws_id,
                content,
            };
            api::submit(&dba, cmd).await.expect("submit SendMessage")
        });
        handles.push(h);
    }
    // Drain the join handles so we know all rows were emitted before
    // we start the wall clock for convergence.
    let mut event_handles = Vec::with_capacity(n);
    for h in handles {
        let eh = h.await.expect("submit task");
        event_handles.push(eh);
    }
    let submit_elapsed = send_start.elapsed();
    eprintln!(
        "[author] submitted {} SendMessage commands in {:.3}s ({:.0} submit/s)",
        n,
        submit_elapsed.as_secs_f64(),
        n as f64 / submit_elapsed.as_secs_f64()
    );

    // Wait for B to converge.
    let db_b_raw = b.handles.runtime.db.clone();
    let outcome = wait_for_messages_on_b(&db_b_raw, &ws.id, n, timeout).await;
    let total_elapsed = send_start.elapsed();

    // Diagnostics.
    let st_a_final = api::endpoint_status(&db_a_arc).await.unwrap();
    let db_b_handle2 = DbHandle::from_runtime(&b.handles);
    let st_b_final = api::endpoint_status(&db_b_handle2).await.unwrap();
    eprintln!(
        "[final] A: applied={} blocked={} pending={}",
        st_a_final.events_applied, st_a_final.events_blocked, st_a_final.events_pending
    );
    eprintln!(
        "[final] B: applied={} blocked={} pending={}",
        st_b_final.events_applied, st_b_final.events_blocked, st_b_final.events_pending
    );
    {
        let g_a = a.handles.runtime.db.lock().await;
        let outbox_a: i64 = g_a.query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0)).unwrap_or(-1);
        let inbound_a: i64 = g_a.query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0)).unwrap_or(-1);
        let msg_a: i64 = g_a.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0)).unwrap_or(-1);
        eprintln!("[final] A: outbox={} inbound_bytes={} messages_proj={}", outbox_a, inbound_a, msg_a);
    }
    {
        let g_b = b.handles.runtime.db.lock().await;
        let outbox_b: i64 = g_b.query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0)).unwrap_or(-1);
        let inbound_b: i64 = g_b.query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0)).unwrap_or(-1);
        let msg_b: i64 = g_b.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0)).unwrap_or(-1);
        eprintln!("[final] B: outbox={} inbound_bytes={} messages_proj={}", outbox_b, inbound_b, msg_b);
    }

    // Tear down both runtimes regardless of outcome (so the workers
    // don't outlive the test).
    drop(db_a_arc);
    let _ = ControlLoopRuntime::shutdown(a.handles).await;
    let _ = ControlLoopRuntime::shutdown(b.handles).await;

    match outcome {
        Ok(converge_secs) => {
            eprintln!();
            eprintln!("===== in-process two-daemon REAL chain perf =====");
            eprintln!("  N                     = {}", n);
            eprintln!(
                "  Submit-on-A wall      = {:.3}s",
                submit_elapsed.as_secs_f64()
            );
            eprintln!("  Convergence-on-B wall = {:.3}s", converge_secs);
            eprintln!(
                "  Total wall            = {:.3}s",
                total_elapsed.as_secs_f64()
            );
            eprintln!(
                "  Throughput            = {:.0} msg/s (total)",
                n as f64 / total_elapsed.as_secs_f64()
            );
            eprintln!(
                "  Sustained             = {:.0} msg/s (convergence-only)",
                n as f64 / converge_secs.max(0.001)
            );
            eprintln!("=================================================");
        }
        Err((count, secs)) => {
            panic!(
                "B did not converge within {}s: {}/{} (elapsed {:.2}s)",
                timeout.as_secs(),
                count,
                n,
                secs
            );
        }
    }
}

fn hex8(id: &[u8; 32]) -> String {
    let s = hex::encode(id);
    s[..8.min(s.len())].to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn inprocess_two_daemon_real_chain_n10() {
    run_inprocess_perf(10, Duration::from_secs(60)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn inprocess_two_daemon_real_chain_n100() {
    run_inprocess_perf(100, Duration::from_secs(60)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn inprocess_two_daemon_real_chain_n1000() {
    run_inprocess_perf(1_000, Duration::from_secs(90)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn inprocess_two_daemon_real_chain_n10000() {
    run_inprocess_perf(10_000, Duration::from_secs(180)).await;
}

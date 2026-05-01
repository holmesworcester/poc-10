//! Performance benchmarks for the **new** ControlLoopRuntime path
//! (TCP -> InboundFrame -> handle_inbound_bytes -> unwrap -> admit ->
//! parse -> context -> project -> apply on the receiver; outbox ->
//! ConnectionSender -> wrap -> TCP send on the sender).
//!
//! This is the new-chain analogue of `tests/perf_test.rs::perf_sync_*`.
//! All tests are `#[ignore]`'d so they only run on demand:
//!
//! ```text
//! cargo test --release --test perf_new_chain_test new_chain_perf_sync_10k -- --ignored --nocapture
//! ```
//!
//! Setup (kept simple — see plan caveat in the task brief):
//! - Two `ControlLoopRuntime` instances on TCP loopback.
//! - Pre-populate connection_endpoints, connection_shared_workspaces,
//!   and outbound/inbound connection_secrets on both sides.
//! - Synthesize N MessageEvents directly into A's events_canonical with
//!   status=Applied + workspace_id set (skipping the heavy real-identity
//!   create-pipeline). The new chain on B applies each MessageEvent
//!   through the registry-driven pure projector path — that's what we
//!   want to measure.
//! - Drain via OutboxWake -> ConnectionSender -> wrap -> transport_v2.
//! - Poll B's events_canonical until N rows have status='applied'.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use rusqlite::params;

use topo::event_modules::connection::secrets::{
    upsert as upsert_secret, SecretDirection, SecretRow,
};
use topo::event_modules::{encode_event, MessageEvent, ParsedEvent};
use topo::runtime::control_loop::work_item::{ConnectionId, EndpointId, WorkspaceId};
use topo::runtime::control_loop::ControlLoopRuntime;
use topo::runtime::jobs::sender::upsert_connection_endpoint;
use topo::state::events_canonical::{self, EventRow, EventScope, EventStatus};
use topo::state::outbox;

/// Read peak resident set size from /proc/self/status (Linux only).
fn peak_rss_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
            // Format: "VmHWM:    12345 kB"
            let kb: f64 = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            return kb / 1024.0;
        }
    }
    0.0
}

/// Build a MessageEvent with the given workspace_id and a deterministic
/// content string. The signature/signed_by/author_id are stub bytes —
/// the new chain doesn't perform an Ed25519 signature check on the
/// inbound side (signer_required is consumed by the projector via
/// `signer_user_mismatch_reason`, which the generic context loader
/// leaves at None — see `src/runtime/control_loop/inbound_step.rs`
/// comment near lines 458-463). The MessageEvent projector applies as
/// long as content is non-empty and the signer/author have no
/// `removed_by:*` label.
fn build_message_event(
    workspace_id: [u8; 32],
    author_id: [u8; 32],
    signed_by: [u8; 32],
    seq: u64,
) -> ParsedEvent {
    ParsedEvent::Message(MessageEvent {
        created_at_ms: 1_000_000 + seq,
        workspace_id,
        author_id,
        content: format!("perf msg #{}", seq),
        signed_by,
        signer_type: 5,
        signature: [0u8; 64],
    })
}

fn blake3_id(bytes: &[u8]) -> [u8; 32] {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

/// Pre-load A and B with the routing the new chain needs to drain.
/// Returns the chosen `workspace_id` and `author_id` so the test can
/// build messages bound to them.
struct ChainHarness {
    handles_a: topo::runtime::control_loop::ControlLoopHandles,
    handles_b: topo::runtime::control_loop::ControlLoopHandles,
    workspace_id: WorkspaceId,
    author_id: [u8; 32],
    signed_by: [u8; 32],
    conn_id: ConnectionId,
}

async fn setup_chain(seed: u8) -> ChainHarness {
    // ---- B (receiver) ----
    let dir_b = tempfile::tempdir().unwrap();
    let db_b_path = dir_b.path().join("perf_chain_b.db");
    // Keep tempdir alive via leak (test is short-lived, drops on process exit).
    std::mem::forget(dir_b);
    let endpoint_b: EndpointId = [seed.wrapping_add(0xB0); 32];
    let bind_b: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let handles_b = ControlLoopRuntime::start(bind_b, endpoint_b, &db_b_path)
        .await
        .expect("B start");
    let addr_b = handles_b.runtime.listen_addr;
    let db_b = handles_b.runtime.db.clone();

    // ---- A (sender) ----
    let dir_a = tempfile::tempdir().unwrap();
    let db_a_path = dir_a.path().join("perf_chain_a.db");
    std::mem::forget(dir_a);
    let endpoint_a: EndpointId = [seed.wrapping_add(0xA0); 32];
    let bind_a: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let handles_a = ControlLoopRuntime::start(bind_a, endpoint_a, &db_a_path)
        .await
        .expect("A start");
    let db_a = handles_a.runtime.db.clone();

    // Seed B's address into the shared OutboxWakeContext.
    let ctx = topo::runtime::control_loop::OutboxWakeContext::current()
        .expect("OutboxWakeContext was installed by ControlLoopRuntime::start");
    ctx.address_book.insert(endpoint_b, addr_b);

    // Connection routing on A.
    let conn_id: ConnectionId = [seed.wrapping_add(0xC0); 32];
    let workspace_id: WorkspaceId = [seed.wrapping_add(0xD0); 32];
    let secret_id: [u8; 32] = [seed.wrapping_add(0xE0); 32];
    let secret_key: [u8; 32] = [seed.wrapping_add(0xF0); 32];
    let author_id: [u8; 32] = [seed.wrapping_add(0xA1); 32];
    let signed_by: [u8; 32] = [seed.wrapping_add(0xA2); 32];

    {
        let g = db_a.lock().await;
        upsert_connection_endpoint(&g, conn_id, endpoint_b).unwrap();
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
    }

    // B's INBOUND secret keyed by the same secret_id.
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

    let _ = endpoint_a; // (kept for symmetry; not used after A's runtime is up)

    ChainHarness {
        handles_a,
        handles_b,
        workspace_id,
        author_id,
        signed_by,
        conn_id,
    }
}

/// Insert N MessageEvents into A's events_canonical (status=Applied,
/// scope=Durable, workspace_id set) and enqueue them on the outbox for
/// `conn_id`. All inside one transaction for speed.
async fn seed_messages_on_a(
    harness: &ChainHarness,
    n: usize,
) {
    let db_a = harness.handles_a.runtime.db.clone();
    let g = db_a.lock().await;
    g.execute("BEGIN", []).unwrap();
    for seq in 0..n {
        let parsed = build_message_event(
            harness.workspace_id,
            harness.author_id,
            harness.signed_by,
            seq as u64,
        );
        let bytes = encode_event(&parsed).unwrap();
        let event_id = blake3_id(&bytes);
        events_canonical::upsert_event(
            &g,
            &EventRow {
                event_id,
                canonical_event_bytes: bytes,
                workspace_id: Some(harness.workspace_id),
                scope: EventScope::Durable,
                status: EventStatus::Applied,
                created_at_ms: seq as i64,
                expires_at_ms: None,
            },
        )
        .unwrap();
        outbox::enqueue(&g, harness.conn_id, event_id, seq as i64).unwrap();
    }
    g.execute("COMMIT", []).unwrap();
}

/// Poll B's events_canonical until at least `n` MessageEvent rows show
/// `status='applied'`. Returns Ok with the wall time when reached, Err
/// with the final count when the deadline passes.
async fn wait_for_applied_on_b(
    harness: &ChainHarness,
    n: usize,
    timeout: Duration,
) -> Result<f64, (i64, f64)> {
    let db_b = harness.handles_b.runtime.db.clone();
    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut last_count = 0i64;
    loop {
        let elapsed = start.elapsed();
        let count: i64 = {
            let g = db_b.lock().await;
            // Count applied rows. We synthesize only Message events on A;
            // B may also have whatever connection-bookkeeping rows the
            // chain creates, so filter on canonical_event_bytes length
            // matching the expected message wire size... actually, just
            // counting status='applied' is fine because the chain only
            // applies events that came in through the wire, and only
            // messages flow on this path.
            g.query_row(
                "SELECT COUNT(*) FROM events_canonical WHERE status='applied'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0)
        };
        if count as usize >= n {
            return Ok(start.elapsed().as_secs_f64());
        }
        if elapsed >= timeout {
            return Err((count, elapsed.as_secs_f64()));
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            let delta = count - last_count;
            eprintln!(
                "[+{}s] B applied: {}/{} (delta: +{}), RSS: {:.0} MiB",
                elapsed.as_secs(),
                count,
                n,
                delta,
                peak_rss_mib(),
            );
            last_count = count;
            last_report = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn run_perf_n(label: &str, n: usize, timeout: Duration, seed: u8) {
    let rss_before = peak_rss_mib();
    let harness = setup_chain(seed).await;

    let gen_start = Instant::now();
    seed_messages_on_a(&harness, n).await;
    let gen_secs = gen_start.elapsed().as_secs_f64();
    eprintln!("Seeded {} message rows on A in {:.2}s", n, gen_secs);

    let outcome = wait_for_applied_on_b(&harness, n, timeout).await;
    let rss_after = peak_rss_mib();

    // Tear down (best-effort).
    let _ = ControlLoopRuntime::shutdown(harness.handles_a).await;
    let _ = ControlLoopRuntime::shutdown(harness.handles_b).await;

    match outcome {
        Ok(wall_secs) => {
            let msgs_per_sec = n as f64 / wall_secs;
            eprintln!();
            eprintln!("=== {} new-chain sync ===", label);
            eprintln!("  Wall time:    {:.2}s", wall_secs);
            eprintln!("  Messages:     {}", n);
            eprintln!("  Msgs/s:       {:.0}", msgs_per_sec);
            eprintln!(
                "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
                rss_after, rss_before, rss_after,
            );
            eprintln!();
        }
        Err((final_count, wall_secs)) => {
            eprintln!();
            eprintln!("=== {} new-chain sync (TIMEOUT) ===", label);
            eprintln!("  Wall time:    {:.2}s", wall_secs);
            eprintln!("  Messages:     {} (target {})", final_count, n);
            eprintln!(
                "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
                rss_after, rss_before, rss_after,
            );
            eprintln!();
            panic!("new-chain perf timed out at {} / {}", final_count, n);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_perf_sync_10k() {
    run_perf_n("10k msg", 10_000, Duration::from_secs(120), 0x10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_perf_sync_50k() {
    run_perf_n("50k msg", 50_000, Duration::from_secs(900), 0x50).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_perf_sync_100k() {
    run_perf_n("100k msg", 100_000, Duration::from_secs(600), 0x90).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_perf_sync_200k() {
    run_perf_n("200k msg", 200_000, Duration::from_secs(900), 0x20).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_perf_sync_500k() {
    run_perf_n("500k msg", 500_000, Duration::from_secs(1800), 0x60).await;
}

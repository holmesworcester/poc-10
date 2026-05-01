//! File throughput perf for the new chain.
//!
//! Builds a file of size N (1 MiB / 10 MiB / 100 MiB), chunks it into
//! 256 KiB slices, computes a real bao outboard for the file
//! plaintext, signs each slice with `slice_hash = blake3(slice_bytes)`,
//! synthesizes the FileEvent + N FileSliceEvent rows on A, and drains
//! through the new chain to B. B's per-slice projector verifies
//! `blake3(slice_bytes) == slice_hash` automatically (see
//! `event_modules/file_slice/projector.rs`).
//!
//! Run with:
//! ```text
//! cargo test --release --test perf_file_throughput_test new_chain_file_throughput_1mib -- --ignored --nocapture
//! ```

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use rusqlite::params;

use topo::event_modules::connection::secrets::{
    upsert as upsert_secret, SecretDirection, SecretRow,
};
use topo::event_modules::{
    encode_event, FileEvent, FileSliceEvent, ParsedEvent,
};
use topo::runtime::control_loop::work_item::{ConnectionId, EndpointId, WorkspaceId};
use topo::runtime::control_loop::ControlLoopRuntime;
use topo::runtime::jobs::sender::upsert_connection_endpoint;
use topo::shared::crypto::bao_verify::compute_outboard;
use topo::state::events_canonical::{self, EventRow, EventScope, EventStatus};
use topo::state::outbox;

/// Slice size matching `file_slice::MAX_SLICE_BYTES`.
const SLICE_BYTES: usize = 256 * 1024;

fn peak_rss_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
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

fn blake3_id(bytes: &[u8]) -> [u8; 32] {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

struct FileHarness {
    handles_a: topo::runtime::control_loop::ControlLoopHandles,
    handles_b: topo::runtime::control_loop::ControlLoopHandles,
    workspace_id: WorkspaceId,
    signed_by: [u8; 32],
    conn_id: ConnectionId,
}

async fn setup_chain(seed: u8) -> FileHarness {
    let dir_b = tempfile::tempdir().unwrap();
    let db_b_path = dir_b.path().join("perf_file_b.db");
    std::mem::forget(dir_b);
    let endpoint_b: EndpointId = [seed.wrapping_add(0xB0); 32];
    let bind_b: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let handles_b = ControlLoopRuntime::start(bind_b, endpoint_b, &db_b_path)
        .await
        .expect("B start");
    let addr_b = handles_b.runtime.listen_addr;
    let db_b = handles_b.runtime.db.clone();

    let dir_a = tempfile::tempdir().unwrap();
    let db_a_path = dir_a.path().join("perf_file_a.db");
    std::mem::forget(dir_a);
    let endpoint_a: EndpointId = [seed.wrapping_add(0xA0); 32];
    let bind_a: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let handles_a = ControlLoopRuntime::start(bind_a, endpoint_a, &db_a_path)
        .await
        .expect("A start");
    let db_a = handles_a.runtime.db.clone();

    let ctx = topo::runtime::control_loop::OutboxWakeContext::current()
        .expect("OutboxWakeContext was installed by ControlLoopRuntime::start");
    ctx.address_book.insert(endpoint_b, addr_b);

    let conn_id: ConnectionId = [seed.wrapping_add(0xC0); 32];
    let workspace_id: WorkspaceId = [seed.wrapping_add(0xD0); 32];
    let secret_id: [u8; 32] = [seed.wrapping_add(0xE0); 32];
    let secret_key: [u8; 32] = [seed.wrapping_add(0xF0); 32];
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

    let _ = endpoint_a;

    FileHarness {
        handles_a,
        handles_b,
        workspace_id,
        signed_by,
        conn_id,
    }
}

/// Build a deterministic file body of `total_bytes` bytes, compute its
/// bao outboard (real bao crate), construct a FileEvent and N
/// FileSliceEvent rows, and insert + enqueue them on A.
///
/// Returns `(file_event_id, slice_count)`.
async fn seed_file_on_a(
    harness: &FileHarness,
    total_bytes: usize,
) -> ([u8; 32], usize) {
    // Build deterministic plaintext.
    let mut data = Vec::with_capacity(total_bytes);
    for i in 0..total_bytes {
        data.push((i as u8).wrapping_mul(7).wrapping_add(13));
    }
    let (root_hash, outboard) = compute_outboard(&data).expect("compute_outboard");

    // Slice it.
    let mut slice_count = total_bytes / SLICE_BYTES;
    if total_bytes % SLICE_BYTES != 0 {
        slice_count += 1;
    }
    if slice_count == 0 {
        slice_count = 1;
    }

    // Build the FileEvent first so we know its event_id (used by slices'
    // file_event_id dep field).
    let file_ev = FileEvent {
        created_at_ms: 1_000_000,
        workspace_id: harness.workspace_id,
        content_hash: root_hash,
        size_bytes: total_bytes as u64,
        slice_count: slice_count as u32,
        signed_by: harness.signed_by,
        signer_type: 5,
        signature: [0u8; 64],
        file_name: format!("perf-{}.bin", total_bytes),
        bao_outboard: outboard,
    };
    let file_blob = encode_event(&ParsedEvent::File(file_ev.clone())).unwrap();
    let file_event_id = blake3_id(&file_blob);

    let db_a = harness.handles_a.runtime.db.clone();
    let g = db_a.lock().await;
    g.execute("BEGIN", []).unwrap();
    // Insert FileEvent.
    events_canonical::upsert_event(
        &g,
        &EventRow {
            event_id: file_event_id,
            canonical_event_bytes: file_blob,
            workspace_id: Some(harness.workspace_id),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();
    outbox::enqueue(&g, harness.conn_id, file_event_id, 0).unwrap();

    // Insert each slice.
    for i in 0..slice_count {
        let start = i * SLICE_BYTES;
        let end = (start + SLICE_BYTES).min(total_bytes);
        let slice_bytes = if end > start {
            data[start..end].to_vec()
        } else {
            Vec::new()
        };
        let slice_hash = blake3_id(&slice_bytes);
        let slice_ev = FileSliceEvent {
            created_at_ms: 1_000_000 + i as u64,
            workspace_id: harness.workspace_id,
            file_event_id,
            slice_index: i as u32,
            slice_hash,
            signed_by: harness.signed_by,
            signer_type: 5,
            signature: [0u8; 64],
            slice_bytes,
        };
        let blob = encode_event(&ParsedEvent::FileSlice(slice_ev)).unwrap();
        let event_id = blake3_id(&blob);
        events_canonical::upsert_event(
            &g,
            &EventRow {
                event_id,
                canonical_event_bytes: blob,
                workspace_id: Some(harness.workspace_id),
                scope: EventScope::Durable,
                status: EventStatus::Applied,
                created_at_ms: 1 + i as i64,
                expires_at_ms: None,
            },
        )
        .unwrap();
        outbox::enqueue(&g, harness.conn_id, event_id, 1 + i as i64).unwrap();
    }
    g.execute("COMMIT", []).unwrap();

    (file_event_id, slice_count)
}

/// Poll B's events_canonical until file + N slice events all reach
/// `status='applied'`. The total expected count is `1 + slice_count`.
async fn wait_for_file_applied_on_b(
    harness: &FileHarness,
    expected_total: usize,
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
            g.query_row(
                "SELECT COUNT(*) FROM events_canonical WHERE status='applied'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0)
        };
        if count as usize >= expected_total {
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
                expected_total,
                delta,
                peak_rss_mib(),
            );
            last_count = count;
            last_report = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn run_file_perf(label: &str, total_bytes: usize, timeout: Duration, seed: u8) {
    let rss_before = peak_rss_mib();
    let harness = setup_chain(seed).await;

    let prep_start = Instant::now();
    let (_file_id, slice_count) = seed_file_on_a(&harness, total_bytes).await;
    let prep_secs = prep_start.elapsed().as_secs_f64();
    eprintln!(
        "Seeded {} bytes ({} slices, +1 file event) on A in {:.2}s",
        total_bytes, slice_count, prep_secs
    );

    let drain_start = Instant::now();
    let outcome = wait_for_file_applied_on_b(&harness, slice_count + 1, timeout).await;
    let drain_secs = drain_start.elapsed().as_secs_f64();
    let rss_after = peak_rss_mib();

    let _ = ControlLoopRuntime::shutdown(harness.handles_a).await;
    let _ = ControlLoopRuntime::shutdown(harness.handles_b).await;

    match outcome {
        Ok(_) => {
            let mib = total_bytes as f64 / (1024.0 * 1024.0);
            let mib_per_sec = mib / drain_secs.max(0.001);
            eprintln!();
            eprintln!("=== {} new-chain file throughput ===", label);
            eprintln!("  Wall time:    {:.2}s", drain_secs);
            eprintln!("  Bytes:        {} ({:.2} MiB)", total_bytes, mib);
            eprintln!("  Slices:       {}", slice_count);
            eprintln!("  MiB/s:        {:.2}", mib_per_sec);
            eprintln!(
                "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
                rss_after, rss_before, rss_after,
            );
            eprintln!();
        }
        Err((count, _)) => {
            eprintln!();
            eprintln!("=== {} new-chain file throughput (TIMEOUT) ===", label);
            eprintln!("  Wall time:    {:.2}s", drain_secs);
            eprintln!(
                "  Applied:      {} / {} (slices+file)",
                count,
                slice_count + 1
            );
            eprintln!(
                "  Peak RSS:     {:.1} MiB (before: {:.1}, after: {:.1})",
                rss_after, rss_before, rss_after,
            );
            eprintln!();
            panic!(
                "file throughput timed out at {} / {}",
                count,
                slice_count + 1
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_file_throughput_1mib() {
    run_file_perf("1 MiB", 1024 * 1024, Duration::from_secs(60), 0x71).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_file_throughput_10mib() {
    run_file_perf("10 MiB", 10 * 1024 * 1024, Duration::from_secs(180), 0x72).await;
}

/// 100 MiB is the brief's target. Possible after raising
/// `EVENT_MAX_BLOB_BYTES` to 64 MiB (Phase-A perf fix): the bao
/// outboard for a 100 MiB plaintext is ~6.4 MB, which now fits inside
/// one substrate event blob. The 15 MiB cap below stays as a regression
/// guard that doesn't depend on the blob-size constant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_file_throughput_15mib() {
    run_file_perf(
        "15 MiB",
        15 * 1024 * 1024,
        Duration::from_secs(180),
        0x73,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn new_chain_file_throughput_100mib() {
    run_file_perf(
        "100 MiB",
        100 * 1024 * 1024,
        Duration::from_secs(600),
        0x74,
    )
    .await;
}

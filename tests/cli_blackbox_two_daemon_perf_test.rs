//! # Two-daemon real-sync black-box performance test
//!
//! Spawns two `topo` daemons as subprocesses and drives them entirely
//! via the CLI. Measures wall-clock from "Daemon A authored N
//! messages" to "Daemon B's `topo messages` shows all N", with the
//! sync hop going through the real connection-bootstrap +
//! compare/have/need/durable-event chain on the wire.
//!
//! Hard requirements (per the task brief):
//! - The `topo` binary is invoked as a subprocess (`Command::new(...)`).
//! - No in-process runtime, no `api::*` calls, no pre-populated
//!   `connection_secrets` rows. Strictly black-box.
//! - The Connection event MUST be authored, signed, and projected
//!   through the chain on both sides — no shortcut.
//! - Sync MUST happen via Compare/Have/Need flowing through the
//!   per-connection sender + transport_v2.
//!
//! The test is `#[ignore]`'d so `cargo test` doesn't run it by
//! accident. Invoke explicitly:
//!
//! ```text
//! cargo test --release --test cli_blackbox_two_daemon_perf_test -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn topo_bin() -> PathBuf {
    // CARGO_BIN_EXE_<name> is exported by cargo for binary targets in
    // the same crate when building integration tests.
    // (https://doc.rust-lang.org/cargo/reference/environment-variables.html)
    PathBuf::from(env!("CARGO_BIN_EXE_topo"))
}

/// Run `topo` as a one-shot subprocess and return its stdout (panics
/// if non-zero status). Used for `create-workspace`, `connect`,
/// `send`, etc.
fn run_cli(args: &[&str]) -> String {
    let bin = topo_bin();
    let out = Command::new(&bin)
        .args(args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .expect("spawn topo");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        panic!(
            "topo {:?} exited with {} \nSTDOUT:\n{}\nSTDERR:\n{}",
            args, out.status, stdout, stderr
        );
    }
    stdout
}

/// Same as `run_cli` but returns Result instead of panicking.
fn try_run_cli(args: &[&str]) -> Result<String, String> {
    let bin = topo_bin();
    let out = Command::new(&bin)
        .args(args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| format!("spawn topo: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(format!("exit={} stdout={} stderr={}", out.status, stdout, stderr));
    }
    Ok(stdout)
}

/// Spawn `topo --db <db> start` in the background, blocking until the
/// listen-address file appears.
struct DaemonHandle {
    child: Child,
    db: PathBuf,
}

impl DaemonHandle {
    fn spawn(db: &std::path::Path, bind: &str) -> Self {
        let bin = topo_bin();
        let log_path = db.with_extension("log");
        let log_file = std::fs::File::create(&log_path).expect("daemon log create");
        let log_file_err = log_file.try_clone().expect("daemon log clone");
        let child = Command::new(&bin)
            .args([
                "--db",
                db.to_str().unwrap(),
                "start",
                "--bind",
                bind,
            ])
            .env(
                "RUST_LOG",
                "topo::runtime::control_loop=debug,topo::runtime::jobs::sender=debug,topo=info",
            )
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("spawn topo start");
        eprintln!(
            "[spawn] daemon db={} log={}",
            db.display(),
            log_path.display()
        );
        // Wait up to 10s for the listen-address file to appear.
        let start = Instant::now();
        let listen_file = listen_addr_file(db);
        while start.elapsed() < Duration::from_secs(10) {
            if listen_file.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !listen_file.exists() {
            panic!(
                "daemon at {} did not write listen file {} within 10s",
                db.display(),
                listen_file.display()
            );
        }
        Self {
            child,
            db: db.to_path_buf(),
        }
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(listen_addr_file(&self.db));
    }
}

fn listen_addr_file(db_path: &std::path::Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    let stem = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "topo.db".to_string());
    p.set_file_name(format!(".{}.listen", stem));
    p
}

/// Count messages on a daemon by parsing `topo messages`.
fn message_count(db: &std::path::Path) -> usize {
    let out = match try_run_cli(&["--db", db.to_str().unwrap(), "messages", "--limit", "0"]) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    out.lines().filter(|l| l.starts_with('[')).count()
}

/// Wait until `pred` returns true, polling every 100ms up to `timeout`.
/// Returns the elapsed time on success.
fn wait_for<F: FnMut() -> bool>(mut pred: F, timeout: Duration) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pred() {
            return Some(start.elapsed());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if pred() {
        Some(start.elapsed())
    } else {
        None
    }
}

/// Parse the workspace id (first 8 hex of the first row) from
/// `topo status`.
fn first_workspace_id_hex(db: &std::path::Path) -> Option<String> {
    let out = run_cli(&["--db", db.to_str().unwrap(), "status"]);
    for line in out.lines() {
        // Format: "  <8hex> :: <name> messages=N users=M"
        let line = line.trim_start();
        if line.contains(" :: ") {
            let id_short = line.split(" :: ").next().map(|s| s.trim().to_string());
            return id_short;
        }
    }
    None
}

#[test]
#[ignore]
fn cli_blackbox_two_daemon_real_sync_smoke() {
    // Smoke variant — N=10, ample timeout. Used to validate the
    // bootstrap path before scaling up.
    run_two_daemon_test(10, Duration::from_secs(60));
}

#[test]
#[ignore]
fn cli_blackbox_two_daemon_real_sync_100() {
    run_two_daemon_test(100, Duration::from_secs(120));
}

#[test]
#[ignore]
fn cli_blackbox_two_daemon_real_sync_1000() {
    run_two_daemon_test(1000, Duration::from_secs(300));
}

#[test]
#[ignore]
fn cli_blackbox_two_daemon_real_sync_10k() {
    run_two_daemon_test(10_000, Duration::from_secs(300));
}

#[test]
#[ignore]
fn cli_blackbox_two_daemon_real_sync_50k() {
    run_two_daemon_test(50_000, Duration::from_secs(600));
}

fn run_two_daemon_test(n: usize, timeout: Duration) {
    let dir_a = tempfile::tempdir().expect("tempdir A");
    let dir_b = tempfile::tempdir().expect("tempdir B");
    let db_a = dir_a.path().join("a.db");
    let db_b = dir_b.path().join("b.db");

    eprintln!("[bootstrap] db_a={} db_b={}", db_a.display(), db_b.display());

    // Leak tempdirs so logs and DBs persist after the test for postmortem.
    std::mem::forget(dir_a);
    std::mem::forget(dir_b);

    // Boot both daemons.
    let _daemon_a = DaemonHandle::spawn(&db_a, "127.0.0.1:0");
    let _daemon_b = DaemonHandle::spawn(&db_b, "127.0.0.1:0");
    eprintln!("[bootstrap] both daemons up");

    // Create a workspace on A.
    let _ = run_cli(&["--db", db_a.to_str().unwrap(), "create-workspace", "perf-ws"]);
    eprintln!("[bootstrap] workspace created on A");

    // Wait for the workspace to materialize in `topo status`.
    let ws_appeared = wait_for(
        || first_workspace_id_hex(&db_a).is_some(),
        Duration::from_secs(10),
    );
    assert!(ws_appeared.is_some(), "workspace did not appear on A");

    // Generate an invite blob from A.
    let invite = run_cli(&["--db", db_a.to_str().unwrap(), "create-invite"]);
    let invite = invite.trim().to_string();
    assert!(!invite.is_empty(), "create-invite produced empty output");
    eprintln!("[bootstrap] invite generated ({} bytes)", invite.len());

    // B accepts the invite (initiates the connection).
    let _ = run_cli(&["--db", db_b.to_str().unwrap(), "connect", &invite]);
    eprintln!("[bootstrap] B connected");

    // Wait for the connection to establish on both sides — we look at
    // the `connection_secrets` table size via `topo status` event
    // counts. Connection event apply is the substrate signal that
    // Connection established. We use a smaller proxy: `events_applied`
    // > 0 on B (B will have applied at least the Connection event).
    let conn_b_applied = wait_for(
        || {
            let s = run_cli(&["--db", db_b.to_str().unwrap(), "status"]);
            s.lines()
                .filter(|l| l.starts_with("events:"))
                .any(|l| l.contains("applied=") && !l.contains("applied=0 "))
        },
        Duration::from_secs(30),
    );
    assert!(
        conn_b_applied.is_some(),
        "Connection event did not apply on B within 30s"
    );
    eprintln!(
        "[bootstrap] Connection applied on B in {:.2}s",
        conn_b_applied.unwrap().as_secs_f64()
    );

    // Author N messages on A. Use the in-process `bench-send`
    // subcommand: one CLI subprocess loops N `api::submit` calls
    // against the running daemon, so subprocess spawn cost (~80 ms)
    // doesn't dominate the wall clock at N=10k / 50k.
    let send_start = Instant::now();
    let n_str = n.to_string();
    let _ = run_cli(&[
        "--db",
        db_a.to_str().unwrap(),
        "bench-send",
        "--count",
        &n_str,
        "--content-prefix",
        "msg",
    ]);
    let send_elapsed = send_start.elapsed();
    eprintln!(
        "[author] N={} authored on A in {:.2}s ({:.1} msg/s)",
        n,
        send_elapsed.as_secs_f64(),
        n as f64 / send_elapsed.as_secs_f64()
    );

    // Wait for B to converge — pure black-box. Uses `topo
    // assert-eventually <pred> --timeout-ms ...`. The substrate-friendly
    // `messages_total` predicate counts `messages` projection rows on
    // the target daemon (no `recorded_by` resolution required, no
    // direct SQLite access from the harness).
    let convergence_start = Instant::now();
    let timeout_ms = timeout.as_millis().to_string();
    let predicate = format!("messages_total >= {}", n);
    let assert_out = run_cli(&[
        "--db",
        db_b.to_str().unwrap(),
        "assert-eventually",
        &predicate,
        "--timeout-ms",
        &timeout_ms,
        "--interval-ms",
        "200",
    ]);
    let convergence_elapsed = convergence_start.elapsed();
    let converged = assert_out.contains("\"pass\":true") || assert_out.contains("pass: true");

    let total = send_elapsed + convergence_elapsed;
    let rate = n as f64 / total.as_secs_f64();

    eprintln!("====================================================");
    eprintln!("Two-daemon real-sync via CLI subprocess");
    eprintln!("N = {}", n);
    eprintln!("Author-on-A wall:        {:.3}s", send_elapsed.as_secs_f64());
    eprintln!(
        "Convergence-on-B wall:   {:.3}s",
        convergence_elapsed.as_secs_f64()
    );
    eprintln!(
        "Total wall (author + sync): {:.3}s ({:.1} msg/s)",
        total.as_secs_f64(),
        rate
    );
    eprintln!("====================================================");

    if !converged {
        for (label, db) in [("A", &db_a), ("B", &db_b)] {
            let log_path = db.with_extension("log");
            if let Ok(s) = std::fs::read_to_string(&log_path) {
                let tail: String = s.lines().rev().take(30).collect::<Vec<_>>().join("\n");
                eprintln!("---- daemon {} log tail ----\n{}", label, tail);
            }
        }
        panic!(
            "B did not converge within {}s (assert-eventually output: {})",
            timeout.as_secs(),
            assert_out.trim()
        );
    }
}

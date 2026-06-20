mod cli_harness;

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::Child;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cli_harness::*;
use rusqlite::{params, Connection};

#[test]
#[ignore = "manual sync throughput fixture; run with cargo test --release -- --ignored when measuring two-daemon catch-up"]
fn black_box_generated_content_sync_perf_uses_daemon_restart_boundary() {
    assert_release_perf_fixture();

    // `generate` authors real message facts in one process so this can measure
    // sync throughput without paying one process start per `send`.
    let tmp = perf_tempdir();
    let alice = temp_db(&tmp.dir, "alice-sync-perf.db");
    let bob = temp_db(&tmp.dir, "bob-sync-perf.db");
    let alice_port = free_port();
    let bob_port = free_port();
    // Keep the ignored fixture quick by default. Use
    // `TOPO_SYNC_PERF_MESSAGES=100000` or `500000` for large catch-up runs.
    let message_count = env_usize("TOPO_SYNC_PERF_MESSAGES").unwrap_or(100);
    let message_text_bytes = env_usize("TOPO_SYNC_PERF_MESSAGE_TEXT_BYTES").unwrap_or(128);
    let preindex_alice = env_bool("TOPO_SYNC_PERF_PREINDEX_ALICE");
    let timeout_ms = env_u64("TOPO_SYNC_PERF_TIMEOUT_MS")
        .unwrap_or_else(|| 120_000_u64.max(message_count as u64 * 120));
    let daemon_tick_ms = env_u64("TOPO_SYNC_PERF_DAEMON_TICK_MS").unwrap_or(100);
    let daemon_quiet_ms = env_u64("TOPO_SYNC_PERF_DAEMON_QUIET_MS").unwrap_or(daemon_tick_ms);

    let workspace = create_workspace(&alice, "sync-perf", "alice", "alice-laptop");
    let invite = workspace_invite_for_addr(&alice, &workspace, alice_port);

    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let accepted = accept_with_identity_retry(&bob, &invite, "bob", "bob-phone");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace);
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);
    create_local_content_key(&alice, &workspace);

    alice_daemon.stop_with_cli();
    bob_daemon.stop_with_cli();

    let alice_indexed_before_generate = sync_indexed_facts(&alice);
    let generated = generate_profiled(&alice, &workspace, message_count, message_text_bytes);
    assert_eq!(
        line_value(&generated.stdout, "generated_facts"),
        message_count.to_string()
    );

    assert_content_count(&bob, &workspace, 0);

    let preindex_started = Instant::now();
    let mut alice_sync_index_ready_ms = 0;
    if preindex_alice {
        let mut alice_daemon = spawn_daemon(&alice, alice_port);
        alice_daemon.assert_running();
        poll_for_sync_indexed_facts(&alice, message_count, Duration::from_millis(timeout_ms));
        alice_sync_index_ready_ms = preindex_started.elapsed().as_millis();
        alice_daemon.stop_with_cli();
    }

    let sync_started = Instant::now();
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let daemons_ready_at = Instant::now();
    alice_daemon.assert_running();
    bob_daemon.assert_running();

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let first_projected = poll_for_content_count(&bob, &workspace, 1, deadline);
    let first_projected_at = Instant::now();
    let projected = poll_for_content_count(&bob, &workspace, message_count, deadline);
    let sync_elapsed = sync_started.elapsed();
    let ready_elapsed = daemons_ready_at.elapsed();
    let sync_to_first_projected = first_projected_at.duration_since(sync_started);
    let ready_to_first_projected = first_projected_at.duration_since(daemons_ready_at);
    let first_to_full_projected = sync_elapsed.saturating_sub(sync_to_first_projected);
    assert_eq!(projected.content_messages, message_count);
    assert!(first_projected.content_messages >= 1);
    let message_timing = projection_timing_stats(&bob, &workspace);
    assert_eq!(message_timing.count, message_count);
    let frame_timing = frame_projection_timing_stats(&bob, &workspace);

    let seconds = sync_elapsed.as_secs_f64().max(0.001);
    let messages_per_second = message_count as f64 / seconds;
    eprintln!(
        "black_box_generated_content_sync_perf db_temp_source={} db_temp_root={} messages={} message_text_bytes={} timeout_ms={} daemon_tick_ms={} daemon_quiet_ms={} preindex_alice={} alice_indexed_before_generate={} alice_sync_index_ready_ms={} authoring_ms={} sync_enable_to_first_projected_ms={} daemons_ready_to_first_projected_ms={} first_projected_to_full_projected_ms={} sync_enable_to_projected_ms={} daemons_ready_to_projected_ms={} messages_per_s={:.2} bob_message_timing_count={} bob_message_timing_with_origin={} bob_message_timing_with_staged={} bob_message_reprojected={} bob_message_max_projection_count={} bob_message_staged_to_first_project_min_ms={} bob_message_staged_to_first_project_p50_ms={} bob_message_staged_to_first_project_p95_ms={} bob_message_staged_to_first_project_max_ms={} bob_message_staged_to_first_project_avg_ms={:.2} bob_message_first_receive_to_project_min_ms={} bob_message_first_receive_to_project_p50_ms={} bob_message_first_receive_to_project_p95_ms={} bob_message_first_receive_to_project_max_ms={} bob_message_first_receive_to_project_avg_ms={:.2} bob_message_latest_receive_to_project_min_ms={} bob_message_latest_receive_to_project_p50_ms={} bob_message_latest_receive_to_project_p95_ms={} bob_message_latest_receive_to_project_max_ms={} bob_message_latest_receive_to_project_avg_ms={:.2} bob_frame_timing_count={} bob_frame_timing_with_origin={} bob_frame_timing_with_staged={} bob_frame_reprojected={} bob_frame_max_projection_count={} bob_frame_staged_to_first_project_min_ms={} bob_frame_staged_to_first_project_p50_ms={} bob_frame_staged_to_first_project_p95_ms={} bob_frame_staged_to_first_project_max_ms={} bob_frame_staged_to_first_project_avg_ms={:.2} bob_frame_first_receive_to_project_min_ms={} bob_frame_first_receive_to_project_p50_ms={} bob_frame_first_receive_to_project_p95_ms={} bob_frame_first_receive_to_project_max_ms={} bob_frame_first_receive_to_project_avg_ms={:.2} bob_frame_latest_receive_to_project_min_ms={} bob_frame_latest_receive_to_project_p50_ms={} bob_frame_latest_receive_to_project_p95_ms={} bob_frame_latest_receive_to_project_max_ms={} bob_frame_latest_receive_to_project_avg_ms={:.2} generate_profile={}",
        tmp.source,
        tmp.root,
        message_count,
        message_text_bytes,
        timeout_ms,
        daemon_tick_ms,
        daemon_quiet_ms,
        preindex_alice,
        alice_indexed_before_generate,
        alice_sync_index_ready_ms,
        generated.elapsed.as_millis(),
        sync_to_first_projected.as_millis(),
        ready_to_first_projected.as_millis(),
        first_to_full_projected.as_millis(),
        sync_elapsed.as_millis(),
        ready_elapsed.as_millis(),
        messages_per_second,
        message_timing.count,
        message_timing.with_origin_received_at,
        message_timing.with_input_staged_at,
        message_timing.reprojected,
        message_timing.max_projection_count,
        message_timing.staged_to_first.min_ms,
        message_timing.staged_to_first.p50_ms,
        message_timing.staged_to_first.p95_ms,
        message_timing.staged_to_first.max_ms,
        message_timing.staged_to_first.avg_ms,
        message_timing.first.min_ms,
        message_timing.first.p50_ms,
        message_timing.first.p95_ms,
        message_timing.first.max_ms,
        message_timing.first.avg_ms,
        message_timing.latest.min_ms,
        message_timing.latest.p50_ms,
        message_timing.latest.p95_ms,
        message_timing.latest.max_ms,
        message_timing.latest.avg_ms,
        frame_timing.count,
        frame_timing.with_origin_received_at,
        frame_timing.with_input_staged_at,
        frame_timing.reprojected,
        frame_timing.max_projection_count,
        frame_timing.staged_to_first.min_ms,
        frame_timing.staged_to_first.p50_ms,
        frame_timing.staged_to_first.p95_ms,
        frame_timing.staged_to_first.max_ms,
        frame_timing.staged_to_first.avg_ms,
        frame_timing.first.min_ms,
        frame_timing.first.p50_ms,
        frame_timing.first.p95_ms,
        frame_timing.first.max_ms,
        frame_timing.first.avg_ms,
        frame_timing.latest.min_ms,
        frame_timing.latest.p50_ms,
        frame_timing.latest.p95_ms,
        frame_timing.latest.max_ms,
        frame_timing.latest.avg_ms,
        one_line(&generated.stderr)
    );
    assert!(messages_per_second.is_finite() && messages_per_second > 0.0);
}

#[test]
#[ignore = "manual live-tail throughput fixture; run with cargo test --release -- --ignored when measuring two-daemon projection without message catch-up"]
fn black_box_generated_content_live_tail_perf_skips_message_catchup() {
    assert_release_perf_fixture();

    // This fixture keeps both daemons connected before generating messages.
    // The measured message window therefore uses live-tail sends emitted by
    // `share_fact_with_sync`, not initial compare/catch-up for the message set.
    let tmp = perf_tempdir();
    let alice = temp_db(&tmp.dir, "alice-live-tail-perf.db");
    let bob = temp_db(&tmp.dir, "bob-live-tail-perf.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let message_count = env_usize("TOPO_SYNC_PERF_MESSAGES").unwrap_or(100);
    let message_text_bytes = env_usize("TOPO_SYNC_PERF_MESSAGE_TEXT_BYTES").unwrap_or(128);
    let timeout_ms = env_u64("TOPO_SYNC_PERF_TIMEOUT_MS")
        .unwrap_or_else(|| 120_000_u64.max(message_count as u64 * 120));
    let daemon_tick_ms = env_u64("TOPO_SYNC_PERF_DAEMON_TICK_MS").unwrap_or(100);
    let daemon_quiet_ms = env_u64("TOPO_SYNC_PERF_DAEMON_QUIET_MS").unwrap_or(daemon_tick_ms);

    let workspace = create_workspace(&alice, "live-tail-perf", "alice", "alice-laptop");
    let invite = workspace_invite_for_addr(&alice, &workspace, alice_port);

    let setup_started = Instant::now();
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let accepted = accept_with_identity_retry(&bob, &invite, "bob", "bob-phone");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace);
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);
    let removal_frontier = create_local_content_key(&alice, &workspace);
    poll_for_key_access(&bob, &workspace, &removal_frontier, "yes", 30_000);
    assert_content_count(&bob, &workspace, 0);
    let setup_ms = setup_started.elapsed().as_millis();

    let generate_started = Instant::now();
    let generated = generate_profiled(&alice, &workspace, message_count, message_text_bytes);
    let generate_finished = Instant::now();
    assert_eq!(
        line_value(&generated.stdout, "generated_facts"),
        message_count.to_string()
    );

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let first_projected = poll_for_content_count(&bob, &workspace, 1, deadline);
    let first_projected_at = Instant::now();
    let projected = poll_for_content_count(&bob, &workspace, message_count, deadline);
    let full_projected_at = Instant::now();
    assert!(first_projected.content_messages >= 1);
    assert_eq!(projected.content_messages, message_count);
    let message_timing = projection_timing_stats(&bob, &workspace);
    assert_eq!(message_timing.count, message_count);
    let frame_timing = frame_projection_timing_stats(&bob, &workspace);

    let generate_start_to_first = first_projected_at.duration_since(generate_started);
    let generate_return_to_first = first_projected_at.saturating_duration_since(generate_finished);
    let generate_return_to_full = full_projected_at.saturating_duration_since(generate_finished);
    let end_to_end = full_projected_at.duration_since(generate_started);
    let live_tail_seconds = generate_return_to_full.as_secs_f64().max(0.001);
    let end_to_end_seconds = end_to_end.as_secs_f64().max(0.001);
    let live_tail_messages_per_second = message_count as f64 / live_tail_seconds;
    let end_to_end_messages_per_second = message_count as f64 / end_to_end_seconds;

    eprintln!(
        "black_box_generated_content_live_tail_perf db_temp_source={} db_temp_root={} messages={} message_text_bytes={} timeout_ms={} daemon_tick_ms={} daemon_quiet_ms={} setup_ms={} authoring_ms={} generate_start_to_first_projected_ms={} generate_return_to_first_projected_ms={} generate_return_to_projected_ms={} generate_start_to_projected_ms={} live_tail_messages_per_s={:.2} end_to_end_messages_per_s={:.2} bob_message_timing_count={} bob_message_timing_with_origin={} bob_message_timing_with_staged={} bob_message_reprojected={} bob_message_max_projection_count={} bob_message_staged_to_first_project_min_ms={} bob_message_staged_to_first_project_p50_ms={} bob_message_staged_to_first_project_p95_ms={} bob_message_staged_to_first_project_max_ms={} bob_message_staged_to_first_project_avg_ms={:.2} bob_message_first_receive_to_project_min_ms={} bob_message_first_receive_to_project_p50_ms={} bob_message_first_receive_to_project_p95_ms={} bob_message_first_receive_to_project_max_ms={} bob_message_first_receive_to_project_avg_ms={:.2} bob_message_latest_receive_to_project_min_ms={} bob_message_latest_receive_to_project_p50_ms={} bob_message_latest_receive_to_project_p95_ms={} bob_message_latest_receive_to_project_max_ms={} bob_message_latest_receive_to_project_avg_ms={:.2} bob_frame_timing_count={} bob_frame_timing_with_origin={} bob_frame_timing_with_staged={} bob_frame_reprojected={} bob_frame_max_projection_count={} bob_frame_staged_to_first_project_min_ms={} bob_frame_staged_to_first_project_p50_ms={} bob_frame_staged_to_first_project_p95_ms={} bob_frame_staged_to_first_project_max_ms={} bob_frame_staged_to_first_project_avg_ms={:.2} bob_frame_first_receive_to_project_min_ms={} bob_frame_first_receive_to_project_p50_ms={} bob_frame_first_receive_to_project_p95_ms={} bob_frame_first_receive_to_project_max_ms={} bob_frame_first_receive_to_project_avg_ms={:.2} bob_frame_latest_receive_to_project_min_ms={} bob_frame_latest_receive_to_project_p50_ms={} bob_frame_latest_receive_to_project_p95_ms={} bob_frame_latest_receive_to_project_max_ms={} bob_frame_latest_receive_to_project_avg_ms={:.2} generate_profile={}",
        tmp.source,
        tmp.root,
        message_count,
        message_text_bytes,
        timeout_ms,
        daemon_tick_ms,
        daemon_quiet_ms,
        setup_ms,
        generated.elapsed.as_millis(),
        generate_start_to_first.as_millis(),
        generate_return_to_first.as_millis(),
        generate_return_to_full.as_millis(),
        end_to_end.as_millis(),
        live_tail_messages_per_second,
        end_to_end_messages_per_second,
        message_timing.count,
        message_timing.with_origin_received_at,
        message_timing.with_input_staged_at,
        message_timing.reprojected,
        message_timing.max_projection_count,
        message_timing.staged_to_first.min_ms,
        message_timing.staged_to_first.p50_ms,
        message_timing.staged_to_first.p95_ms,
        message_timing.staged_to_first.max_ms,
        message_timing.staged_to_first.avg_ms,
        message_timing.first.min_ms,
        message_timing.first.p50_ms,
        message_timing.first.p95_ms,
        message_timing.first.max_ms,
        message_timing.first.avg_ms,
        message_timing.latest.min_ms,
        message_timing.latest.p50_ms,
        message_timing.latest.p95_ms,
        message_timing.latest.max_ms,
        message_timing.latest.avg_ms,
        frame_timing.count,
        frame_timing.with_origin_received_at,
        frame_timing.with_input_staged_at,
        frame_timing.reprojected,
        frame_timing.max_projection_count,
        frame_timing.staged_to_first.min_ms,
        frame_timing.staged_to_first.p50_ms,
        frame_timing.staged_to_first.p95_ms,
        frame_timing.staged_to_first.max_ms,
        frame_timing.staged_to_first.avg_ms,
        frame_timing.first.min_ms,
        frame_timing.first.p50_ms,
        frame_timing.first.p95_ms,
        frame_timing.first.max_ms,
        frame_timing.first.avg_ms,
        frame_timing.latest.min_ms,
        frame_timing.latest.p50_ms,
        frame_timing.latest.p95_ms,
        frame_timing.latest.max_ms,
        frame_timing.latest.avg_ms,
        one_line(&generated.stderr)
    );
    assert!(live_tail_messages_per_second.is_finite() && live_tail_messages_per_second > 0.0);

    alice_daemon.stop_with_cli();
    bob_daemon.stop_with_cli();
}

struct PerfTempDir {
    dir: tempfile::TempDir,
    source: String,
    root: String,
}

fn perf_tempdir() -> PerfTempDir {
    let configured_root = std::env::var("TOPO_SYNC_PERF_TMPDIR").ok();
    let dir = if let Some(root) = configured_root.as_deref() {
        fs::create_dir_all(root).expect("create TOPO_SYNC_PERF_TMPDIR");
        tempfile::Builder::new()
            .prefix("topo-sync-perf-")
            .tempdir_in(root)
            .expect("create perf tempdir in TOPO_SYNC_PERF_TMPDIR")
    } else {
        tempfile::Builder::new()
            .prefix("topo-sync-perf-")
            .tempdir()
            .expect("create perf tempdir")
    };
    let source = configured_root
        .as_ref()
        .map(|_| "TOPO_SYNC_PERF_TMPDIR")
        .unwrap_or("tempfile_default")
        .to_string();
    let root = temp_root_for_log(dir.path());
    PerfTempDir { dir, source, root }
}

fn temp_root_for_log(path: &Path) -> String {
    path.parent()
        .unwrap_or(path)
        .to_string_lossy()
        .replace(' ', "%20")
}

struct RunningDaemon {
    child: Option<Child>,
    label: String,
    db: String,
    stdout: Option<JoinHandle<String>>,
    stderr: Option<JoinHandle<String>>,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.join_output();
    }
}

impl RunningDaemon {
    fn assert_running(&mut self) {
        let child = self.child.as_mut().expect("daemon child");
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!("daemon {} exited early: {status}", self.label),
            Err(err) => panic!("poll daemon {}: {err}", self.label),
        }
    }

    fn stop_with_cli(&mut self) {
        let stopped = assert_success(topo(&["--db", &self.db, "stop"]));
        assert!(
            stopped.contains("stopped daemon") || stopped.contains("daemon process exited"),
            "unexpected stop output for {}:\n{stopped}",
            self.label
        );
        if let Some(mut child) = self.child.take() {
            let status = child.wait().expect("wait daemon after stop");
            assert!(
                status.success(),
                "daemon {} exited with {status}",
                self.label
            );
        }
        self.join_output();
    }

    fn join_output(&mut self) {
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            if let Ok(text) = stderr.join() {
                if !text.trim().is_empty() {
                    eprintln!("[daemon-stderr label={}] {}", self.label, text.trim_end());
                }
            }
        }
    }
}

fn spawn_daemon(db: &str, port: u16) -> RunningDaemon {
    let port_str = port.to_string();
    let tick_ms = env_u64("TOPO_SYNC_PERF_DAEMON_TICK_MS")
        .unwrap_or(100)
        .to_string();
    let quiet_ms = env_u64("TOPO_SYNC_PERF_DAEMON_QUIET_MS")
        .unwrap_or_else(|| tick_ms.parse::<u64>().expect("tick ms parses"))
        .to_string();
    let mut child = spawn_topo_with_env(
        &[
            "--db",
            db,
            "start",
            "--listen",
            "127.0.0.1",
            &port_str,
            "--sync-ms",
            &tick_ms,
            "--quiet-ms",
            &quiet_ms,
        ],
        &[("TOPO_PROFILE_PROJECTION_TIMING", "1")],
    );
    let stdout = child.stdout.take().expect("daemon stdout");
    let stderr = child.stderr.take().expect("daemon stderr");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read daemon line");
    assert!(
        line.starts_with("listening: "),
        "daemon did not report listening: {line}"
    );
    let stdout_handle = thread::spawn(move || {
        let mut text = String::new();
        let _ = reader.read_to_string(&mut text);
        text
    });
    let stderr_handle = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut text = String::new();
        let _ = reader.read_to_string(&mut text);
        text
    });
    RunningDaemon {
        child: Some(child),
        label: format!("{db}@{port}"),
        db: db.to_string(),
        stdout: Some(stdout_handle),
        stderr: Some(stderr_handle),
    }
}

fn create_workspace(db: &str, name: &str, username: &str, device_name: &str) -> String {
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
    ]));
    line_value(&out, "workspace_id")
}

fn workspace_invite_for_addr(db: &str, workspace_id: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&[
        "--db",
        db,
        "invite",
        "--workspace",
        workspace_id,
        "--public-addr",
        &addr,
    ]));
    out.lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{out}"))
        .to_string()
}

fn accept_with_identity_retry(db: &str, invite: &str, username: &str, device_name: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept",
            invite,
            "--username",
            username,
            "--devicename",
            device_name,
        ]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") && !last.contains("user invite was not received") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("accept failed: {last}");
}

fn poll_for_workspace_member(db: &str, workspace_id: &str, username: &str, timeout_ms: u64) {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while Instant::now() < deadline {
        let recipient = topo(&["--db", db, "key-recipient", workspace_id]);
        let users = topo(&["--db", db, "users", workspace_id]);
        if recipient.status.success() && users.status.success() {
            let text = stdout(&users);
            if text.contains(username) {
                return;
            }
            last = text;
        } else {
            last = format!(
                "key-recipient stderr:\n{}\nusers stderr:\n{}",
                stderr(&recipient),
                stderr(&users)
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("user {username} did not converge into {db}; last users output:\n{last}");
}

fn create_local_content_key(db: &str, workspace_id: &str) -> String {
    let frontier = assert_success(topo(&["--db", db, "key-frontier", workspace_id]));
    wait_for_keys_value(db, workspace_id, "local_key_secrets", "1");
    wait_for_keys_value(db, workspace_id, "removal_frontiers", "1");
    line_value(&frontier, "removal_frontier_id")
}

fn wait_for_keys_value(db: &str, workspace_id: &str, key: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "keys", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, key) == expected {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("keys {key} never reached {expected}: {last}");
}

fn sync_indexed_facts(db: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "sync-status"]));
    line_value(&out, "indexed_facts")
        .parse::<usize>()
        .expect("indexed_facts usize")
}

fn poll_for_sync_indexed_facts(db: &str, expected: usize, timeout: Duration) -> usize {
    let deadline = Instant::now() + timeout;
    loop {
        let indexed = sync_indexed_facts(db);
        if indexed >= expected {
            return indexed;
        }
        if Instant::now() >= deadline {
            panic!("sync-status indexed_facts >= {expected} timed out, last observed {indexed}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn poll_for_key_access(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    expected: &str,
    timeout_ms: u64,
) {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while Instant::now() < deadline {
        let out = topo(&["--db", db, "key-access", workspace_id, removal_frontier_id]);
        if out.status.success() {
            let text = stdout(&out);
            if line_value(&text, "access") == expected {
                return;
            }
            last = text;
        } else {
            last = stderr(&out);
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("key-access did not reach {expected} in {db}; last output:\n{last}");
}

#[derive(Debug)]
struct GenerateRun {
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

fn generate_profiled(db: &str, workspace: &str, count: usize, size: usize) -> GenerateRun {
    let count = count.to_string();
    let size = size.to_string();
    let started = Instant::now();
    let output = con_cli_with_env(
        &["--db", db, "generate", workspace, &count, &size],
        &[("TOPO_PROFILE_GENERATE", "1")],
    );
    let elapsed = started.elapsed();
    assert!(
        output.status.success(),
        "generate failed\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    GenerateRun {
        stdout: stdout(&output),
        stderr: stderr(&output),
        elapsed,
    }
}

fn assert_content_count(db: &str, workspace: &str, expected: usize) {
    let count = content_count(db, workspace);
    assert_eq!(
        count.content_messages, expected,
        "content-count messages mismatch for {db}"
    );
}

fn poll_for_content_count(
    db: &str,
    workspace: &str,
    expected: usize,
    deadline: Instant,
) -> ContentCount {
    let mut last = content_count(db, workspace);
    while Instant::now() < deadline {
        if last.content_messages >= expected {
            return last;
        }
        thread::sleep(Duration::from_millis(500));
        last = content_count(db, workspace);
    }
    panic!(
        "content-count {workspace} content_messages >= {expected} timed out, last observed {}",
        last.content_messages
    );
}

#[derive(Debug)]
struct ContentCount {
    content_messages: usize,
}

fn content_count(db: &str, workspace: &str) -> ContentCount {
    let workspace_id = decode_hex_32(workspace);
    let conn = Connection::open(db).expect("open content count db");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("set busy timeout");
    ContentCount {
        content_messages: conn
            .query_row(
                "SELECT COUNT(*)
                 FROM content_messages
                 WHERE workspace_id = ?1",
                params![workspace_id],
                |row| row.get::<_, i64>(0).map(|value| value as usize),
            )
            .expect("query content message count"),
    }
}

#[derive(Debug)]
struct ProjectionTimingStats {
    count: usize,
    with_origin_received_at: usize,
    with_input_staged_at: usize,
    reprojected: usize,
    max_projection_count: i64,
    staged_to_first: LatencyStats,
    first: LatencyStats,
    latest: LatencyStats,
}

#[derive(Debug)]
struct LatencyStats {
    min_ms: i64,
    p50_ms: i64,
    p95_ms: i64,
    max_ms: i64,
    avg_ms: f64,
}

#[derive(Debug)]
struct ProjectionTimingRow {
    received_at: i64,
    origin_received_at: Option<i64>,
    input_staged_at: Option<i64>,
    first_projected_at: i64,
    projected_at: i64,
    projection_count: i64,
}

fn projection_timing_stats(db: &str, workspace: &str) -> ProjectionTimingStats {
    message_projection_timing_stats(db, workspace)
}

fn message_projection_timing_stats(db: &str, workspace: &str) -> ProjectionTimingStats {
    let workspace_id = decode_hex_32(workspace);
    let conn = Connection::open(db).expect("open projection timing db");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("set busy timeout");
    let mut stmt = conn
        .prepare(
            "SELECT
                t.received_at,
                t.origin_received_at,
                t.input_staged_at,
                t.first_projected_at,
                t.projected_at,
                t.projection_count
             FROM content_messages m
             JOIN projection_timings t ON t.fact_id = m.message_id
             WHERE m.workspace_id = ?1",
        )
        .expect("prepare projection timing query");
    let rows = stmt
        .query_map(params![workspace_id], |row| {
            Ok(ProjectionTimingRow {
                received_at: row.get(0)?,
                origin_received_at: row.get(1)?,
                input_staged_at: row.get(2)?,
                first_projected_at: row.get(3)?,
                projected_at: row.get(4)?,
                projection_count: row.get(5)?,
            })
        })
        .expect("query projection timings")
        .map(|row| row.expect("projection timing row"))
        .collect::<Vec<_>>();
    stats_from_timing_rows(rows, "message projection timing")
}

fn frame_projection_timing_stats(db: &str, workspace: &str) -> ProjectionTimingStats {
    let workspace_id = decode_hex_32(workspace);
    let conn = Connection::open(db).expect("open frame projection timing db");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("set busy timeout");
    let mut stmt = conn
        .prepare(
            "WITH message_origins(origin_received_at) AS (
                SELECT DISTINCT t.origin_received_at
                FROM content_messages m
                JOIN projection_timings t ON t.fact_id = m.message_id
                WHERE m.workspace_id = ?1
                  AND t.origin_received_at IS NOT NULL
             )
             SELECT
                t.received_at,
                t.origin_received_at,
                t.input_staged_at,
                t.first_projected_at,
                t.projected_at,
                t.projection_count
             FROM projection_timings t
             JOIN message_origins o ON o.origin_received_at = t.origin_received_at
             WHERE t.fact_type IN (168, 169, 170)",
        )
        .expect("prepare frame projection timing query");
    let rows = stmt
        .query_map(params![workspace_id], |row| {
            Ok(ProjectionTimingRow {
                received_at: row.get(0)?,
                origin_received_at: row.get(1)?,
                input_staged_at: row.get(2)?,
                first_projected_at: row.get(3)?,
                projected_at: row.get(4)?,
                projection_count: row.get(5)?,
            })
        })
        .expect("query frame projection timings")
        .map(|row| row.expect("frame projection timing row"))
        .collect::<Vec<_>>();
    stats_from_timing_rows(rows, "frame projection timing")
}

fn stats_from_timing_rows(rows: Vec<ProjectionTimingRow>, label: &str) -> ProjectionTimingStats {
    let count = rows.len();
    assert!(count > 0, "{label} stats require at least one row");
    let with_origin_received_at = rows
        .iter()
        .filter(|row| row.origin_received_at.is_some())
        .count();
    let with_input_staged_at = rows
        .iter()
        .filter(|row| row.input_staged_at.is_some())
        .count();
    let reprojected = rows.iter().filter(|row| row.projection_count > 1).count();
    let max_projection_count = rows
        .iter()
        .map(|row| row.projection_count)
        .max()
        .unwrap_or(0);
    let first_latencies = rows
        .iter()
        .map(|row| {
            let baseline = row.origin_received_at.unwrap_or(row.received_at);
            row.first_projected_at.saturating_sub(baseline).max(0)
        })
        .collect::<Vec<_>>();
    let staged_to_first_latencies = rows
        .iter()
        .filter_map(|row| {
            row.input_staged_at
                .map(|staged_at| row.first_projected_at.saturating_sub(staged_at).max(0))
        })
        .collect::<Vec<_>>();
    assert!(
        !staged_to_first_latencies.is_empty(),
        "{label} stats require at least one staged row"
    );
    let latest_latencies = rows
        .iter()
        .map(|row| {
            let baseline = row.origin_received_at.unwrap_or(row.received_at);
            row.projected_at.saturating_sub(baseline).max(0)
        })
        .collect::<Vec<_>>();
    ProjectionTimingStats {
        count,
        with_origin_received_at,
        with_input_staged_at,
        reprojected,
        max_projection_count,
        staged_to_first: latency_stats(staged_to_first_latencies),
        first: latency_stats(first_latencies),
        latest: latency_stats(latest_latencies),
    }
}

fn latency_stats(mut latencies: Vec<i64>) -> LatencyStats {
    latencies.sort();
    let count = latencies.len();
    let sum = latencies.iter().map(|latency| *latency as f64).sum::<f64>();
    LatencyStats {
        min_ms: percentile_latency(&latencies, 0),
        p50_ms: percentile_latency(&latencies, 50),
        p95_ms: percentile_latency(&latencies, 95),
        max_ms: percentile_latency(&latencies, 100),
        avg_ms: sum / count as f64,
    }
}

fn percentile_latency(latencies: &[i64], percentile: usize) -> i64 {
    assert!(!latencies.is_empty(), "latencies must not be empty");
    let last = latencies.len() - 1;
    let index = ((last * percentile) + 99) / 100;
    latencies[index.min(last)]
}

fn decode_hex_32(value: &str) -> Vec<u8> {
    assert_eq!(value.len(), 64, "workspace id must be hex32");
    let mut out = Vec::with_capacity(32);
    for index in 0..32 {
        let high = hex_nibble(value.as_bytes()[index * 2]);
        let low = hex_nibble(value.as_bytes()[index * 2 + 1]);
        out.push((high << 4) | low);
    }
    out
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("non-hex byte {byte}"),
    }
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a positive integer"))
        })
        .filter(|value| *value > 0)
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a positive integer"))
        })
        .filter(|value| *value > 0)
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            !(normalized.is_empty() || normalized == "0" || normalized == "false")
        })
        .unwrap_or(false)
}

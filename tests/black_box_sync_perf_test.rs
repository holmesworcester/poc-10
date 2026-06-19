mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cli_harness::*;
use rusqlite::{params, Connection};

#[test]
#[ignore = "manual sync throughput fixture; run with --ignored when measuring two-daemon catch-up"]
fn black_box_generated_content_sync_perf_uses_daemon_restart_boundary() {
    // `generate` authors real message facts in one process so this can measure
    // sync throughput without paying one process start per `send`.
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-sync-perf.db");
    let bob = temp_db(&tmp, "bob-sync-perf.db");
    let alice_port = free_port();
    let bob_port = free_port();
    // Keep the ignored fixture quick by default. Use
    // `TOPO_SYNC_PERF_MESSAGES=100000` or `500000` for large catch-up runs.
    let message_count = env_usize("TOPO_SYNC_PERF_MESSAGES").unwrap_or(100);
    let message_text_bytes = env_usize("TOPO_SYNC_PERF_MESSAGE_TEXT_BYTES").unwrap_or(128);
    let timeout_ms = env_u64("TOPO_SYNC_PERF_TIMEOUT_MS")
        .unwrap_or_else(|| 120_000_u64.max(message_count as u64 * 120));

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

    let generated = generate_profiled(&alice, &workspace, message_count, message_text_bytes);
    assert_eq!(
        line_value(&generated.stdout, "generated_facts"),
        message_count.to_string()
    );

    assert_content_count(&bob, &workspace, 0);

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

    let seconds = sync_elapsed.as_secs_f64().max(0.001);
    let messages_per_second = message_count as f64 / seconds;
    eprintln!(
        "black_box_generated_content_sync_perf messages={} message_text_bytes={} timeout_ms={} authoring_ms={} sync_enable_to_first_projected_ms={} daemons_ready_to_first_projected_ms={} first_projected_to_full_projected_ms={} sync_enable_to_projected_ms={} daemons_ready_to_projected_ms={} messages_per_s={:.2} generate_profile={}",
        message_count,
        message_text_bytes,
        timeout_ms,
        generated.elapsed.as_millis(),
        sync_to_first_projected.as_millis(),
        ready_to_first_projected.as_millis(),
        first_to_full_projected.as_millis(),
        sync_elapsed.as_millis(),
        ready_elapsed.as_millis(),
        messages_per_second,
        one_line(&generated.stderr)
    );
    assert!(messages_per_second.is_finite() && messages_per_second > 0.0);
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
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port_str,
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
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

//! Black-box CLI tests for the replay entry point and deterministic state
//! summary.
//!
//! Setup goes through the real `con` binary: a workspace and content messages
//! are authored, then `replay` rebuilds derived state from retained facts. The
//! tests prove the replay/intent-shape guarantees: replay is idempotent, drops
//! queued intents, recreates sync- and key-wrap-derived state, never crosses the
//! network barrier, and reaches the same state digest regardless of fact
//! projection order.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use cli_harness::*;

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
    let workspace_id = line_value(&out, "workspace_id");
    wait_for_users_contains(db, &workspace_id, username);
    wait_for_identity_contains(db, "endpoint_role=device");
    workspace_id
}

fn seed_workspace_with_content(db: &str) -> String {
    let _daemon = spawn_worker_daemon(db);
    let workspace_id = create_workspace(db, "Replay", "alice", "laptop");
    create_local_content_key(db, &workspace_id);
    assert_success(topo(&["--db", db, "send", &workspace_id, "first message"]));
    wait_for_message_text(db, &workspace_id, "alice: first message");
    assert_success(topo(&["--db", db, "send", &workspace_id, "second message"]));
    wait_for_message_text(db, &workspace_id, "alice: second message");
    wait_for_runtime_idle(db);
    workspace_id
}

struct StartedDaemon {
    db: String,
    child: Child,
}

impl Drop for StartedDaemon {
    fn drop(&mut self) {
        let _ = topo(&["--db", &self.db, "stop"]);
        let _ = self.child.wait();
    }
}

fn spawn_worker_daemon(db: &str) -> StartedDaemon {
    let port = free_port().to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port,
        "--tick-ms",
        "25",
        "--quiet-ms",
        "25",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    if let Some(stderr) = child.stderr.take() {
        thread::spawn(move || for _ in BufReader::new(stderr).lines() {});
    }
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read daemon ready line");
    assert!(line.contains("listening:"), "daemon did not start: {line}");
    StartedDaemon {
        db: db.to_string(),
        child,
    }
}

fn wait_for_runtime_idle(db: &str) {
    let started = Instant::now();
    let timeout = Duration::from_secs(10);
    loop {
        let last = assert_success(topo(&["--db", db, "count"]));
        let facts: u64 = line_value(&last, "facts").parse().expect("facts count");
        let applied: u64 = line_value(&last, "applied_facts")
            .parse()
            .expect("applied facts count");
        let pending_intents: u64 = line_value(&last, "pending_intents")
            .parse()
            .expect("pending intents count");
        if facts == applied && pending_intents == 0 {
            return;
        }
        assert!(
            started.elapsed() < timeout,
            "daemon did not drain runtime queues:\n{last}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn create_local_content_key(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "key-frontier", workspace_id]));
    wait_for_keys_value(db, workspace_id, "local_key_secrets", "1");
    wait_for_keys_value(db, workspace_id, "removal_frontiers", "1");
    out
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
    panic!("keys {key} did not reach {expected}:\n{last}");
}

fn wait_for_message_text(db: &str, workspace_id: &str, expected_suffix: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "messages", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if out
                .lines()
                .any(|line| line.trim_end().ends_with(expected_suffix))
            {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("message text {expected_suffix:?} never appeared in {db}:\n{last}");
}

fn wait_for_users_contains(db: &str, workspace_id: &str, username: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let users = topo(&["--db", db, "users", workspace_id]);
        if users.status.success() {
            let users = stdout(&users);
            if users.contains(username) {
                return;
            }
            last = users;
        } else {
            last = stderr(&users);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("user {username} never appeared in {db}: {last}");
}

fn wait_for_identity_contains(db: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let identity = topo(&["--db", db, "identity"]);
        if identity.status.success() {
            let identity = stdout(&identity);
            if identity.contains(expected) {
                return;
            }
            last = identity;
        } else {
            last = stderr(&identity);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("identity never contained {expected}: {last}");
}

fn state_hash(db: &str) -> String {
    line_value(
        &assert_success(topo(&["--db", db, "state-summary"])),
        "state_hash",
    )
}

struct RunningDaemon {
    child: Child,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(db: &str, port: u16) -> RunningDaemon {
    let port = port.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port,
        "--tick-ms",
        "50",
        "--quiet-ms",
        "50",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    reader.read_line(&mut first).expect("daemon first line");
    assert!(
        first.starts_with("listening: "),
        "daemon did not report listening: {first}"
    );
    RunningDaemon { child }
}

#[test]
fn replay_is_idempotent_and_rebuilds_derived_state() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = seed_workspace_with_content(&db);

    let before = state_hash(&db);

    let replay = assert_success(topo(&["--db", &db, "replay"]));
    assert_eq!(
        line_value(&replay, "order"),
        "canonical",
        "default replay uses canonical fact order"
    );
    assert_eq!(
        line_value(&replay, "network_rows"),
        "0",
        "replay must not produce network rows before the barrier"
    );
    assert!(
        line_value(&replay, "retained_facts")
            .parse::<u64>()
            .unwrap()
            > 0,
        "replay should reproject retained facts"
    );
    assert!(
        line_value(&replay, "row_mutations").parse::<u64>().unwrap() > 0,
        "replay should rebuild materialized read-model rows"
    );
    assert!(
        line_value(&replay, "replayed_intents")
            .parse::<u64>()
            .unwrap()
            > 0,
        "replay should recreate sync and key-wrap work through replay dispatch"
    );

    let after = state_hash(&db);
    assert_eq!(before, after, "replay must rebuild byte-identical state");

    // The rebuilt read model still answers content queries.
    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(messages.contains("first message"), "{messages}");
    assert!(messages.contains("second message"), "{messages}");
}

#[test]
fn second_replay_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    assert_success(topo(&["--db", &db, "replay"]));
    let once = state_hash(&db);
    assert_success(topo(&["--db", &db, "replay"]));
    let twice = state_hash(&db);
    assert_eq!(once, twice, "replay is idempotent");
}

#[test]
fn replay_reverse_rebuilds_same_state_as_canonical() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let before = state_hash(&db);
    let replay = assert_success(topo(&["--db", &db, "replay", "--reverse"]));
    assert_eq!(line_value(&replay, "order"), "reverse");
    assert_eq!(line_value(&replay, "network_rows"), "0");
    let after = state_hash(&db);
    assert_eq!(
        before, after,
        "reverse projection order must reach the same state"
    );
}

#[test]
fn replay_scramble_rebuilds_same_state_as_canonical() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let before = state_hash(&db);
    let replay = assert_success(topo(&["--db", &db, "replay", "--scramble", "--seed", "7"]));
    assert_eq!(line_value(&replay, "order"), "scramble:7");
    assert_eq!(line_value(&replay, "network_rows"), "0");
    let after = state_hash(&db);
    assert_eq!(
        before, after,
        "scrambled projection order must reach the same state"
    );
}

#[test]
fn replay_check_reports_identical_digest_across_orders() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let out = assert_success(topo(&["--db", &db, "replay-check"]));
    assert_eq!(line_value(&out, "ok"), "true", "{out}");
    assert_eq!(line_value(&out, "mismatched_passes"), "0", "{out}");
    assert_eq!(
        line_value(&out, "passes"),
        "6",
        "canonical, idempotent, reverse, and three scrambled passes"
    );

    // replay-check works on scratch copies and must not mutate the live db.
    let live_before = state_hash(&db);
    assert_success(topo(&["--db", &db, "replay-check"]));
    assert_eq!(
        state_hash(&db),
        live_before,
        "replay-check must not mutate the live database"
    );
}

fn area_line(summary: &str, area: &str) -> String {
    summary
        .lines()
        .find(|line| line.starts_with(&format!("area_{area}:")))
        .unwrap_or_else(|| panic!("state-summary missing area {area}:\n{summary}"))
        .to_string()
}

fn area_count(summary: &str, area: &str) -> u64 {
    let line = area_line(summary, area);
    line.split_whitespace()
        .nth(1)
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("state-summary area {area} count is invalid: {line}"))
}

fn wait_for_area_count_at_least(db: &str, area: &str, expected_min: u64) -> String {
    let mut last = String::new();
    for _ in 0..40 {
        let output = topo(&["--db", db, "state-summary"]);
        if output.status.success() {
            let summary = stdout(&output);
            if area_count(&summary, area) >= expected_min {
                return summary;
            }
            last = summary;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("state-summary area {area} did not reach {expected_min}:\n{last}");
}

#[test]
fn replay_recreates_key_material_idempotently() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let daemon_port = free_port();
    let _daemon = spawn_daemon(&db, daemon_port);
    let workspace_id = create_workspace(&db, "Keys", "alice", "laptop");
    create_local_content_key(&db, &workspace_id);
    assert_success(topo(&["--db", &db, "key-recipient", &workspace_id]));
    assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_id,
        "secret message",
    ]));
    wait_for_runtime_idle(&db);

    let summary_before = wait_for_area_count_at_least(&db, "key_wrap_rows", 1);
    let key_wrap_before = area_line(&summary_before, "key_wrap_rows");
    // The recipient scenario materializes at least one key wrap.
    let key_wrap_count = area_count(&summary_before, "key_wrap_rows");
    assert!(key_wrap_count > 0, "{key_wrap_before}");
    let before = state_hash(&db);

    let replay = assert_success(topo(&["--db", &db, "replay"]));
    // create_key_wrap / unwrap_key_wrap run during replay as deterministic fact
    // creation. They must not duplicate any wrap or local-secret fact, so replay
    // emits no new facts and purges none.
    assert_eq!(
        line_value(&replay, "emitted_facts"),
        "0",
        "replay key-material handlers must not create duplicate facts"
    );
    assert_eq!(line_value(&replay, "purged_facts"), "0");
    assert_eq!(line_value(&replay, "network_rows"), "0");
    assert!(
        line_value(&replay, "replayed_intents")
            .parse::<u64>()
            .unwrap()
            > 0,
        "replay should redispatch key-material work"
    );

    let after = state_hash(&db);
    assert_eq!(before, after, "key material must rebuild identically");
    let summary_after = assert_success(topo(&["--db", &db, "state-summary"]));
    assert_eq!(
        area_line(&summary_after, "key_wrap_rows"),
        key_wrap_before,
        "key wrap rows must be byte-identical after replay"
    );
}

#[test]
fn state_summary_is_stable_and_exposes_per_area_digests() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let first = assert_success(topo(&["--db", &db, "state-summary"]));
    let second = assert_success(topo(&["--db", &db, "state-summary"]));
    assert_eq!(first, second, "state summary is a stable read");
    assert!(
        first.lines().any(|line| line.starts_with("area_facts:")),
        "state summary exposes the retained facts area: {first}"
    );
    assert!(
        first
            .lines()
            .any(|line| line.starts_with("area_content_messages:")),
        "state summary exposes the materialized message rows area: {first}"
    );
    // Volatile scheduler/socket state is excluded from the digest areas.
    assert!(
        !first
            .lines()
            .any(|line| line.starts_with("area_network_outgoing:")
                || line.starts_with("area_intents:")
                || line.starts_with("area_pending_projection:")),
        "state summary must exclude volatile scheduler and socket state: {first}"
    );
}

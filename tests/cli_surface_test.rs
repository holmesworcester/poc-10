//! CLI surface tests for slice 5 + negentropy purge functionality.
//!
//! These tests cover the new operator-facing commands added to expose
//! slice 5 + negentropy purge mechanisms end-to-end. They are kept
//! separate from `tests/disappearing_messages_cli_test.rs` (which
//! covers FS / cascade / minute-expiry behavior) so each file has a
//! single responsibility.
//!
//! Surface under test:
//!   * `disappearing-set` auto-advances the floor every call (and
//!     rejects regressing the floor when `--floor` is supplied below
//!     the previous value).
//!   * `disappearing-status` round-trips the active policy,
//!     horizon progress, and message + tombstone counts.
//!   * `disappearing-tighten --yes` advances the floor and the
//!     dispatcher then deletes pre-floor messages.
//!   * `disappearing-compact` advances the floor without touching the
//!     TTL.
//!   * `sync-status` succeeds and reports the root summary.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;

// ---------------------------------------------------------------------------
// Test 1: `disappearing-set` advances the floor automatically; a second
// call with the same TTL after a clock advance also advances the floor.
// This is the "every set is a floor-advance opportunity" contract.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_set_advances_floor_automatically() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    let workspace_id = create_workspace_with_ttl(&alice, "AutoFloor", "alice", "alice-laptop", 5);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // First set at minute 100, TTL=5: auto floor = max(0, 100 - 5) = 95.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let first = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "5",
    ]));
    assert_eq!(line_value(&first, "ttl_minutes"), "5");
    assert_eq!(line_value(&first, "previous_floor_minute"), "0");
    assert_eq!(line_value(&first, "new_floor_minute"), "95");
    assert_eq!(line_value(&first, "floor_delta_minutes"), "95");

    // Advance the clock to minute 200. Re-issue the same TTL: auto floor
    // should be max(95, 200 - 5) = 195. Same TTL; the floor still advances.
    assert_success(topo(&["--db", &alice, "clock", "set", "12000000"]));
    let second = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "5",
    ]));
    assert_eq!(line_value(&second, "previous_floor_minute"), "95");
    assert_eq!(line_value(&second, "new_floor_minute"), "195");
    assert_eq!(line_value(&second, "floor_delta_minutes"), "100");
}

// ---------------------------------------------------------------------------
// Test 2: `disappearing-set --floor <below-previous>` exits non-zero
// with the projector's monotonicity error and does NOT mutate the
// active policy. This is the operator-facing equivalent of the
// projector test that rejects a policy whose floor is below the previous floor.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_set_explicit_floor_below_previous_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    let workspace_id = create_workspace_with_ttl(&alice, "Mono", "alice", "alice-laptop", 5);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Establish a previous floor = 95.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let first = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "5",
    ]));
    assert_eq!(line_value(&first, "new_floor_minute"), "95");

    // Try to regress to floor=10. Must fail.
    let regress = topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "5",
        "--floor",
        "10",
    ]);
    assert!(
        !regress.status.success(),
        "regressing floor must fail:\nstdout={}\nstderr={}",
        stdout(&regress),
        stderr(&regress)
    );
    let err = stderr(&regress);
    assert!(
        err.contains("monotonic non-decreasing"),
        "error must surface the projector's wording:\n{err}"
    );

    // The active policy must be unchanged: status still shows 95.
    let status = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-status",
        &workspace_id,
    ]));
    assert_eq!(line_value(&status, "current_floor_minute"), "95");
}

// ---------------------------------------------------------------------------
// Test 3: `disappearing-status` reports every documented field after a
// known setup. Uses no daemon — we stage the workspace, set a known
// TTL/floor, send a couple of messages, and check that each line of
// output reflects the on-disk state.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_status_round_trips_known_setup() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    let workspace_id = create_workspace_with_ttl(&alice, "Status", "alice", "alice-laptop", 5);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin clock to minute 100.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let set_out = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "5",
    ]));
    let policy_fact_id = line_value(&set_out, "policy_fact_id");

    // Author 2 messages so live_messages == 2.
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "hello"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "world"]));

    let status = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-status",
        &workspace_id,
    ]));
    assert_eq!(line_value(&status, "workspace"), workspace_id);
    assert_eq!(line_value(&status, "policy_fact_id"), policy_fact_id);
    assert_eq!(line_value(&status, "current_ttl_minutes"), "5");
    assert_eq!(line_value(&status, "current_floor_minute"), "95");
    assert_eq!(line_value(&status, "now_minute"), "100");
    // horizon_floor = max(0, 100 - 30*24*60) = 0
    assert_eq!(line_value(&status, "horizon_floor"), "0");
    assert_eq!(line_value(&status, "effective_floor"), "95");
    assert_eq!(line_value(&status, "live_messages"), "2");
    assert_eq!(line_value(&status, "message_tombstones"), "0");
    assert_eq!(line_value(&status, "leaf_tombstones"), "0");
    // The cover horizon has not advanced, so no horizon floor is reported.
    assert_eq!(line_value(&status, "last_chopped_floor"), "none");
}

// ---------------------------------------------------------------------------
// Test 4: `disappearing-tighten --yes` advances the floor on the
// issuing peer; spinning up the daemon to drive the dispatcher then
// deletes the pre-floor messages. We do not assert cross-peer sync
// (slice 5 already covers convergence in a separate test).
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_tighten_yes_deletes_pre_floor_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    // Use a generous initial TTL so the messages stay live until the
    // tighten call moves the floor under them.
    let workspace_id = create_workspace_with_ttl(&alice, "Tighten", "alice", "alice-laptop", 60);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin clock to minute 100. Author 2 messages stamped at minute 100
    // with TTL=60 (expires_at_minute = 160 — well past the test window).
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "stale-1"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "stale-2"]));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);

    // Spawn the daemon BEFORE the tighten so projection work runs inside
    // the polling window.
    let _daemon = spawn_daemon(&alice, alice_port);

    // Advance clock to minute 200. Tighten with TTL=5: target floor =
    // 200 - 5 = 195. Both authored messages are at minute 100 < 195, so
    // both fall under the new floor.
    assert_success(topo(&["--db", &alice, "clock", "set", "12000000"]));
    let tighten = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-tighten",
        &workspace_id,
        "5",
        "--yes",
    ]));
    assert_eq!(line_value(&tighten, "ttl_minutes"), "5");
    assert_eq!(line_value(&tighten, "previous_floor_minute"), "0");
    assert_eq!(line_value(&tighten, "new_floor_minute"), "195");
    assert_eq!(line_value(&tighten, "messages_below_floor"), "2");

    // Wait for the retention projection to settle. Minute-expiry has likely already
    // retired the messages (clock = 200 > 100 + 60 = 160), but the
    // tighten's floor advancement is what we're proving end-to-end:
    // `disappearing-status::current_floor_minute` jumps to 195.
    let mut last_status = String::new();
    for _ in 0..300 {
        last_status = assert_success(topo(&[
            "--db",
            &alice,
            "disappearing-status",
            &workspace_id,
        ]));
        if line_value(&last_status, "current_floor_minute") == "195"
            && line_value(&last_status, "live_messages") == "0"
        {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        line_value(&last_status, "current_floor_minute"),
        "195",
        "tighten must advance the floor:\n{last_status}"
    );
    assert_eq!(
        line_value(&last_status, "live_messages"),
        "0",
        "messages below the floor must be deleted:\n{last_status}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: an explicit retention floor retires messages below the floor while
// retaining messages at or above it.
// ---------------------------------------------------------------------------

#[test]
fn cli_retention_floor_deletes_below_floor_messages_and_retains_above_floor_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id =
        create_workspace_with_ttl(&alice, "Retention Floor", "alice", "alice-laptop", 1000);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &alice, "clock", "set", "3000000"]));
    assert_success(topo(&[
        "--db",
        &alice,
        "send",
        &workspace_id,
        "below floor",
    ]));
    assert_success(topo(&["--db", &alice, "clock", "set", "12000000"]));
    assert_success(topo(&[
        "--db",
        &alice,
        "send",
        &workspace_id,
        "above floor",
    ]));

    let pre_messages = messages_text(&alice, &workspace_id);
    assert!(
        pre_messages.contains("alice: below floor"),
        "{pre_messages}"
    );
    assert!(
        pre_messages.contains("alice: above floor"),
        "{pre_messages}"
    );

    let floor = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "1000",
        "--floor",
        "100",
    ]));
    assert_eq!(line_value(&floor, "previous_floor_minute"), "0");
    assert_eq!(line_value(&floor, "new_floor_minute"), "100");

    let status = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-status",
        &workspace_id,
    ]));
    assert_eq!(line_value(&status, "current_floor_minute"), "100");

    let post_messages = messages_text(&alice, &workspace_id);
    assert!(
        !post_messages.contains("alice: below floor"),
        "retention floor must retire below-floor opened message rows:\n{post_messages}"
    );
    assert!(
        post_messages.contains("alice: above floor"),
        "retention floor must retain above-floor content rows:\n{post_messages}"
    );
    let count = assert_success(topo(&["--db", &alice, "content-count", &workspace_id]));
    assert_eq!(line_value(&count, "content_messages"), "1");
}

// ---------------------------------------------------------------------------
// Test 6: `disappearing-compact` advances the floor without changing
// the TTL. Live messages stamped under the current policy survive
// (their `expires_at_minute >= new_floor` by construction); only debris
// is GC'd.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_compact_advances_floor_without_changing_ttl() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    let workspace_id = create_workspace_with_ttl(&alice, "Compact", "alice", "alice-laptop", 30);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin clock to minute 100. Set TTL=30 with the default auto floor
    // (= 100 - 30 = 70).
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "30",
    ]));
    let pre = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-status",
        &workspace_id,
    ]));
    assert_eq!(line_value(&pre, "current_ttl_minutes"), "30");
    assert_eq!(line_value(&pre, "current_floor_minute"), "70");

    // Author a live message stamped under TTL=30 (expires at minute 130).
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "live"]));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    // Advance clock to minute 200 (still past the message's expiry, but
    // the test author didn't run the daemon so no expiry happens — the
    // message remains in the live table). Compact pushes the floor to
    // max(70, 200 - 30) = 170; TTL stays at 30.
    assert_success(topo(&["--db", &alice, "clock", "set", "12000000"]));
    let compact = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-compact",
        &workspace_id,
    ]));
    assert_eq!(line_value(&compact, "ttl_minutes"), "30");
    assert_eq!(line_value(&compact, "previous_floor_minute"), "70");
    assert_eq!(line_value(&compact, "new_floor_minute"), "170");
    assert_eq!(line_value(&compact, "floor_delta_minutes"), "100");

    // Active policy reflects the new floor; TTL is unchanged.
    let post = assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-status",
        &workspace_id,
    ]));
    assert_eq!(line_value(&post, "current_ttl_minutes"), "30");
    assert_eq!(line_value(&post, "current_floor_minute"), "170");
}

// ---------------------------------------------------------------------------
// Test 7: `sync-status` after expiry reports a changed root summary.
//
// Setup: author messages, then expire them by advancing the clock past
// the TTL horizon. We then call `sync-status` directly to verify
// the CLI command succeeds and the root summary reflects the disappeared
// messages.
// ---------------------------------------------------------------------------

#[test]
fn cli_sync_status_reports_root_after_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "Drain", "alice", "alice-laptop", 1);
    let daemon = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin clock to minute 100; author 3 messages.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    for body in ["a", "b", "c"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), 3);
    wait_for_sync_root_count_at_least(&alice, 3);

    // Capture the pre-expiry root fingerprint via `sync-status`.
    let pre = assert_success(topo(&["--db", &alice, "sync-status"]));
    let pre_fp = line_value(&pre, "root_fingerprint");
    let pre_count: u64 = line_value(&pre, "root_count").parse().expect("count");
    assert!(
        !pre.contains("drained:") && !pre.contains("new_root_count:"),
        "`sync-status` should not expose the retired drain output shape:\n{pre}"
    );
    assert!(
        pre_count >= 3,
        "indexed facts must include at least the 3 authored messages: {pre_count}"
    );

    // Spawn the daemon to advance the messages through expiry, then stop it
    // before invoking the command explicitly.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");
    drop(daemon);

    // After the daemon stops, the command must still succeed and report
    // a post-expiry root summary.
    let post = assert_success(topo(&["--db", &alice, "sync-status"]));
    let post_fp = line_value(&post, "root_fingerprint");
    assert_eq!(post_fp.len(), pre_fp.len(), "{post}");
    let post_count: u64 = line_value(&post, "root_count").parse().expect("post count");
    assert!(post_count > 0, "{post}");
}

// ---------------------------------------------------------------------------
// Helpers (local to this test file). Mirrors the helpers in
// `tests/disappearing_messages_cli_test.rs` but kept self-contained
// so this file can evolve independently.
// ---------------------------------------------------------------------------

fn create_workspace_with_ttl(
    db: &str,
    name: &str,
    username: &str,
    device_name: &str,
    ttl_minutes: u32,
) -> String {
    let ttl = ttl_minutes.to_string();
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
        "--ttl-minutes",
        &ttl,
    ]));
    line_value(&out, "workspace_id")
}

fn message_lines(db: &str, workspace_id: &str) -> Vec<String> {
    let out = assert_success(topo(&["--db", db, "messages", workspace_id]));
    out.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && line.contains(". [")
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

fn wait_for_leaf_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "keys", workspace_id]));
        if line_value(&out, "local_history_leaves") == expected {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("leaf count did not reach {expected}:\n{last}");
}

fn wait_for_sync_root_count_at_least(db: &str, expected_min: u64) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "sync-status"]));
        let count: u64 = line_value(&out, "root_count").parse().expect("root count");
        if count >= expected_min {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("sync root count did not reach {expected_min}:\n{last}");
}

fn wait_for_content_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "content-count", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "content_messages") == expected {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("content count did not reach {expected}:\n{last}");
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

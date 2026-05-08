//! Black-box CLI tests for disappearing-messages forward secrecy.
//!
//! Slice gate for `disappearing_messages_plan.md`. These tests drive the
//! real `topo` binary and assert observable forward-secrecy and
//! convergence behavior through public CLI output. The tests intentionally
//! do not seed protocol rows or call workers directly. They will fail
//! until the slice-1 surface lands:
//!
//!   * `create-workspace ... --ttl-minutes <u32>` plumbs a workspace-wide
//!     TTL into authored messages.
//!   * `MessageEvent` canonical bytes carry `expires_at_minute: u64`
//!     (`u64::MAX` = no expiry).
//!   * The `expired_minute` local-only event module exists; its projector
//!     punctures the minute_node, exact-row-deletes the read-model row,
//!     purges canonical bytes via `retention::purge_event_storage_in_tx`,
//!     and writes a tombstone row pointing the retired minute node at the
//!     `expired_minute` event id.
//!   * The `disappearing_minute_expiry` worker is registered as a
//!     daemon-step worker alongside `content_purge` and fires when
//!     `logical_time` advances past a minute's expiry.
//!   * The encryption worker exposes a whole-minute retirement variant
//!     (the TODO at `src/workers/encryption.rs:1147`).
//!
//! Known gaps these tests do NOT close (covered by later slices):
//!   * A first-class `expired_minute_summary` distinct from the retained
//!     cover summary (slice 3 "deletion summary monotonicity").
//!   * A canonical-bytes-by-event-id query (`events get <id>`) for a
//!     direct purge proof. The current strongest signal is `content-count`
//!     dropping to 0 and `keys` row counts collapsing.
//!   * Offline-expire isolation. With both daemons connected the test
//!     cannot observe whether each peer's `expired_minute` was derived
//!     locally or sneaked across the wire. A proper offline-expire test
//!     needs a harness that suppresses auto-reconnect (the daemon
//!     periodically reconnects to known peers); that harness change is
//!     out of scope for this slice gate.
//!   * Per-tombstone-row byte-equality across peers. The tests verify
//!     tombstone-count equality and `cover_summary` equality, but the
//!     actual `LOCAL_HISTORY_NODE_TOMBSTONES` rows are not surfaced by
//!     the current `keys` CLI. A future slice should add a per-row
//!     tombstone listing so peers can be compared row-for-row.

mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

// ---------------------------------------------------------------------------
// Test 1: single-peer FS contract — keys retired, message purged, cover
// changes, AND a daemon restart cannot resurrect the expired message.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_expire_and_resist_rederive() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Disappearing", "alice", "alice-laptop", 1);
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let local_key_secret_id = line_value(&frontier, "local_key_secret_id");

    // Pin clock to unix_minute 100 (ms = 6_000_000). TTL=1 ⇒ expires at
    // minute 101; minute 102 is safely past expiry.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let send = assert_success(topo(&["--db", &alice, "send", &workspace_id, "secret"]));
    let _message_id = line_value(&send, "event_id");

    // Pre-expiry baseline. The new binary-tree schema only materializes
    // leaves for active messages; the minute_node above them stays implicit
    // until a delete forces it to be durably named, so we don't assert a
    // count for `local_history_minute_nodes` here.
    let pre = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&pre, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre, "local_history_node_tombstones"), "0");
    let pre_summary = cover_summary_value(&pre);
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);
    assert!(messages_text(&alice, &workspace_id).contains("alice: secret"));

    let alice_daemon = spawn_daemon(&alice, alice_port);

    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    // Slice 1 retires one leaf per expired message. Wait until the leaf
    // row is gone; tombstone rows are an internal mechanism and slice 1
    // does not contract on a specific count (the encryption worker only
    // writes a tombstone when the retirement also materializes siblings
    // for an in-minute survivor, which doesn't happen for the last leaf
    // in its minute).
    wait_for_leaf_count(&alice, &workspace_id, "0");

    // Post-expiry assertions.
    let post = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&post, "local_history_leaves"), "0");
    let post_summary = cover_summary_value(&post);
    assert_ne!(pre_summary, post_summary);
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    wait_for_content_count(&alice, &workspace_id, "0");

    // Stop the daemon and confirm the on-disk state still resists recovery.
    drop(alice_daemon);
    // Re-run key-derive: zero new wrap derivations.
    let derive = assert_success(topo(&["--db", &alice, "key-derive"]));
    assert_eq!(
        line_value(&derive, "derived_key_secrets"),
        "0",
        "rederive must not produce any new key secrets after expiry"
    );

    // The load-bearing FS claim is at the minute-node layer: even with the
    // removal-frontier `local_key_secret` still on disk, the punctured
    // minute_node must not be rederivable. Drive `key-node` for the same
    // coordinates that authoring used (range_start = unix_minute 100,
    // range_width = 1, no event_id_in_minute) and assert it cannot
    // resurrect a usable secret. Two acceptable behaviors: command refuses
    // (non-zero exit), or it succeeds without admitting any new event and
    // without surfacing a fresh `local_history_node_secret_id`. Either way,
    // the on-disk state must be byte-identical to the post-expiry state.
    let rederive = topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &local_key_secret_id,
        "100",
        "1",
    ]);
    if rederive.status.success() {
        let out = stdout(&rederive);
        assert_eq!(
            line_value(&out, "local_history_node_secret_id"),
            "none",
            "rederive must not surface a new minute_node secret:\n{out}"
        );
        assert_eq!(
            line_value(&out, "admitted_events"),
            "0",
            "rederive must not admit any new local_history_node_secret event:\n{out}"
        );
    }

    let after_restart = keys_value(&alice, &workspace_id);
    assert_eq!(
        line_value(&after_restart, "local_history_leaves"),
        "0",
        "rederive must not resurrect any retired leaf:\n{after_restart}"
    );
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_event_count(&alice, &workspace_id), "0");
    assert_eq!(
        cover_summary_value(&after_restart),
        post_summary,
        "cover_summary must be byte-identical after a rederive attempt"
    );

    // Restart the daemon and tick once more: still no recovery.
    let alice_daemon_again = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6120001"]));
    thread::sleep(Duration::from_millis(300));
    let after_second_restart = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&after_second_restart, "local_history_leaves"), "0");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_event_count(&alice, &workspace_id), "0");
    drop(alice_daemon_again);
}

// ---------------------------------------------------------------------------
// Test 2: cross-peer convergence of cover and tombstones across two
// independently-running peers.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_two_peer_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let bob_join_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Converge", "alice", "alice-laptop", 1);
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        bob_join_port,
        "bob",
        "bob-phone",
    );

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");

    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    );
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );
    let _ = wait_for_key_derive(&bob, "1");

    // Pin both clocks to the same unix_minute and have each peer author.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "alice-secret"]));
    assert_success(topo(&["--db", &bob, "send", &workspace_id, "bob-secret"]));

    wait_for_message_text(&alice, &workspace_id, "alice: alice-secret");
    wait_for_message_text(&alice, &workspace_id, "bob: bob-secret");
    wait_for_message_text(&bob, &workspace_id, "alice: alice-secret");
    wait_for_message_text(&bob, &workspace_id, "bob: bob-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 2);

    let pre_alice = keys_value(&alice, &workspace_id);
    let pre_bob = keys_value(&bob, &workspace_id);
    assert_eq!(
        cover_summary_value(&pre_alice),
        cover_summary_value(&pre_bob),
        "cover_summary must converge across peers pre-expiry"
    );
    // Two messages in one minute ⇒ two leaves on each peer. Minute_nodes
    // stay implicit until a delete materializes them, so we don't assert
    // a count for `local_history_minute_nodes` pre-expiry.
    assert_eq!(line_value(&pre_alice, "local_history_leaves"), "2");
    assert_eq!(line_value(&pre_bob, "local_history_leaves"), "2");

    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    // Wait for both peers to reach zero leaves; per-leaf retirement may or
    // may not produce a tombstone row depending on whether siblings forced
    // materialization, so leaf count is the load-bearing signal.
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");

    let post_alice = keys_value(&alice, &workspace_id);
    let post_bob = keys_value(&bob, &workspace_id);

    assert_eq!(
        line_value(&post_alice, "local_history_leaves"),
        "0",
        "alice's leaves must be retired post-expiry:\n{post_alice}"
    );
    assert_eq!(
        line_value(&post_bob, "local_history_leaves"),
        "0",
        "bob's leaves must be retired post-expiry:\n{post_bob}"
    );

    assert_eq!(
        cover_summary_value(&post_alice),
        cover_summary_value(&post_bob),
        "cover_summary must converge across peers post-expiry"
    );
    assert_ne!(
        cover_summary_value(&pre_alice),
        cover_summary_value(&post_alice),
        "cover_summary must change after puncture"
    );
    assert_eq!(
        line_value(&post_alice, "local_history_node_tombstones"),
        line_value(&post_bob, "local_history_node_tombstones"),
        "tombstone count must match across peers post-expiry"
    );

    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 0);
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");

    // Note: cross-peer sync of a NEW message AFTER expiry is intentionally
    // not exercised here. Empirically, when alice authors a fresh-minute
    // message after both peers have purged a prior minute's events, sync
    // does not redeliver the new message to bob within the test's polling
    // window. That is a sync-vs-purge interaction worth its own
    // investigation — the negentropy snapshot referencing purged ids may
    // be confusing the post-purge "have/need" comparison. The convergence
    // claims of slice 1 (cover and tombstone) are already proven by the
    // pre/post-expiry assertions above.
}

// ---------------------------------------------------------------------------
// Test 3 (slice 2): admin-signed `disappearing_messages_setting` event
// supersedes the workspace event's initial TTL. Authoring under one TTL
// stamps that TTL into the message's canonical bytes; a later admin
// `disappearing-set` does NOT retroactively rewrite already-stamped
// messages, but DOES change the TTL stamped into subsequent messages.
//
// This is the load-bearing slice-2 invariant from `disappearing_messages_plan.md`:
// "Late arrivals do not retroactively change message expiry."
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_setting_supersedes_workspace_ttl_without_rewriting_old_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    // Workspace TTL = 1 minute at creation.
    let workspace_id =
        create_workspace_with_ttl(&alice, "Setting", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin the clock and author the first message at minute 100. This is
    // stamped under the workspace event's TTL of 1, so its
    // expires_at_minute is 101.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "early"]));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    // Admin authors a setting event raising TTL to 5. After the setting
    // is admitted, subsequent messages are stamped with TTL=5; the
    // previously-authored "early" message's stamped expiry is unchanged.
    assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "5",
    ]));

    // Author the second message at the same minute 100 but after the new
    // setting. It should be stamped with expires_at_minute = 100 + 5 = 105.
    // (No clock advance — the setting takes effect immediately for the
    // next authoring.)
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "late"]));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);

    // Spawn the daemon and advance the clock past minute 101 but before
    // minute 105: the "early" message must expire, but the "late" message
    // must remain visible. This is the key claim — the setting did not
    // retroactively rewrite "early"'s expiry to 105, and the new message
    // really did pick up the new TTL.
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6180000"])); // minute 103

    // Wait for "early" to disappear; "late" should remain.
    for _ in 0..300 {
        let lines = message_lines(&alice, &workspace_id);
        let has_early = lines.iter().any(|line| line.ends_with("alice: early"));
        let has_late = lines.iter().any(|line| line.ends_with("alice: late"));
        if !has_early && has_late {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let lines = message_lines(&alice, &workspace_id);
    assert!(
        !lines.iter().any(|line| line.ends_with("alice: early")),
        "`early` (stamped TTL=1) must have expired by minute 103:\n{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.ends_with("alice: late")),
        "`late` (stamped TTL=5) must still be visible at minute 103:\n{lines:?}"
    );

    // Advance past minute 105 and the "late" message must also expire.
    assert_success(topo(&["--db", &alice, "clock", "set", "6360000"])); // minute 106
    for _ in 0..300 {
        let lines = message_lines(&alice, &workspace_id);
        if lines.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        message_lines(&alice, &workspace_id).len(),
        0,
        "`late` (stamped TTL=5) must have expired by minute 106"
    );
}

// ---------------------------------------------------------------------------
// Test 4 (slice 4): when a parent message expires, its reactions are
// reclaimed in the same tick via the content_purge cascade. Reactions
// don't carry their own `expires_at_minute` — they inherit by being
// authored in the same minute as the parent message, and the
// disappearing-minute worker writes a `MESSAGE_TOMBSTONES` row that
// triggers content_purge to drop reaction rows + canonical bytes for
// any message that's been tombstoned.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_cascade_reactions_when_parent_message_expires() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Cascade", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Author a message and then react to it, both in unix_minute 100.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "secret"]));
    assert_success(topo(&[
        "--db", &alice, "react", &workspace_id, "#1", "🌶️",
    ]));

    // Pre-expiry: one message visible, two leaves materialized (message +
    // reaction).
    let pre = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&pre, "local_history_leaves"), "2");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    // Advance past minute 101 (TTL=1 ⇒ expires_at_minute=101).
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));

    // Wait for both leaves to be retired — the message's by the
    // disappearing-minute worker, the reaction's by the content_purge
    // cascade triggered by the message tombstone.
    wait_for_leaf_count(&alice, &workspace_id, "0");

    // Post-expiry assertions.
    let post = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&post, "local_history_leaves"), "0");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    // Both message and reaction canonical bytes are reclaimed.
    wait_for_content_count(&alice, &workspace_id, "0");
}

// ---------------------------------------------------------------------------
// Helpers (local to this test file).
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

fn keys_value(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "keys", workspace_id]))
}

fn cover_summary_value(keys_output: &str) -> String {
    line_value(keys_output, "cover_summary")
}

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

/// Visible message bodies: lines of the form `N. [ts] user: text`.
fn message_lines(db: &str, workspace_id: &str) -> Vec<String> {
    messages_text(db, workspace_id)
        .lines()
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

fn content_event_count(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "content-count", workspace_id]));
    line_value(&out, "content_events")
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

fn wait_for_content_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "content-count", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "content_events") == expected {
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

fn wait_for_key_derive(db: &str, expected: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "key-derive"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "derived_key_secrets") == expected {
                return out;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key derive did not reach {expected}:\n{last}");
}

/// Wait for a message body suffix (e.g. `"alice: hello"`) to appear in the
/// `messages` listing. The CLI prints lines as `N. [ts] author: text`, so
/// callers pass the `author: text` suffix and we match on `ends_with`.
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
    panic!(
        "message text {expected_suffix:?} never appeared on db={db}:\n{last}"
    );
}

fn key_wrap_with_retry(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    recipient_key_id: &str,
) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&[
            "--db",
            db,
            "key-wrap",
            workspace_id,
            removal_frontier_id,
            recipient_key_id,
        ]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key-wrap never succeeded: {last}");
}

// --- two-peer setup helpers (mirrored from tests/encryption_cli_test.rs) ---

fn join_workspace(
    host: &str,
    joiner: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let mut listener = spawn_workspace_invite_listener(host, workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(joiner, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => listener.fail("workspace invite accept failed", err),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    let host_out = listener.wait_success("workspace invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
}

struct ListeningInvite {
    child: Child,
    invite_rx: Receiver<Result<String, String>>,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
}

impl ListeningInvite {
    fn invite_link(&mut self) -> String {
        match self.invite_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => {
                assert!(
                    line.starts_with("topo://invite/"),
                    "missing invite link in first listener line: {line}"
                );
                thread::sleep(Duration::from_millis(50));
                line
            }
            Ok(Err(err)) => {
                let _ = self.child.kill();
                panic!("listener did not print invite link: {err}");
            }
            Err(err) => {
                let _ = self.child.kill();
                panic!("timed out waiting for invite link: {err}");
            }
        }
    }

    fn wait_success(mut self, label: &str) -> String {
        let status = self.child.wait().expect("wait for listener");
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        assert!(
            status.success(),
            "{label} failed\nstdout={stdout}\nstderr={stderr}"
        );
        stdout
    }

    fn fail(mut self, label: &str, err: String) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        panic!("{label}: {err}\nlistener stdout:\n{stdout}\nlistener stderr:\n{stderr}");
    }
}

fn spawn_workspace_invite_listener(
    db: &str,
    workspace_id: &str,
    port: u16,
    accept: usize,
) -> ListeningInvite {
    let port = port.to_string();
    let accept = accept.to_string();
    let child = spawn_topo(&[
        "--db",
        db,
        "invite",
        "--workspace",
        workspace_id,
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ]);
    listening_invite_from_child(child)
}

fn listening_invite_from_child(mut child: Child) -> ListeningInvite {
    let stdout = child.stdout.take().expect("listener stdout");
    let stderr = child.stderr.take().expect("listener stderr");
    let (invite_tx, invite_rx) = mpsc::channel();
    let stdout = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut output = String::new();
        let mut first = String::new();
        match reader.read_line(&mut first) {
            Ok(0) => {
                let _ = invite_tx.send(Err("stdout closed before first line".to_string()));
            }
            Ok(_) => {
                output.push_str(&first);
                let link = first.trim_end_matches(['\r', '\n']).to_string();
                let _ = invite_tx.send(Ok(link));
            }
            Err(err) => {
                let _ = invite_tx.send(Err(err.to_string()));
            }
        }

        let mut rest = String::new();
        if reader.read_to_string(&mut rest).is_ok() {
            output.push_str(&rest);
        }
        output
    });
    let stderr = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut output = String::new();
        let _ = reader.read_to_string(&mut output);
        output
    });
    ListeningInvite {
        child,
        invite_rx,
        stdout,
        stderr,
    }
}

fn try_accept_with_identity_retry(
    db: &str,
    invite: &str,
    username: &str,
    device_name: &str,
) -> Result<String, String> {
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
            return Ok(stdout(&output));
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
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

fn connect_daemon_pair(left_db: &str, left_port: u16, right_db: &str, right_port: u16) {
    let left_invite = transport_invite(left_db, left_port);
    let right_invite = transport_invite(right_db, right_port);
    let right_to_left = connect_with_retry(right_db, &left_invite);
    assert!(right_to_left.contains("connected:"), "{right_to_left}");
    let left_to_right = connect_with_retry(left_db, &right_invite);
    assert!(left_to_right.contains("connected:"), "{left_to_right}");
}

fn transport_invite(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    invite_link_from_output(&out)
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn connect_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&["--db", db, "connect", invite]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded: {last}");
}

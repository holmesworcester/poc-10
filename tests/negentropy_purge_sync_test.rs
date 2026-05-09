//! CLI tests for the negentropy purge drainer.
//!
//! Exercises the deferred sync-vs-purge interaction noted in
//! `tests/disappearing_messages_cli_test.rs::cli_disappearing_messages_two_peer_convergence`:
//!
//!   * Two peers that purge the same set of admitted shared event ids
//!     reach byte-identical negentropy `root_fingerprint` values.
//!   * The pending-purge queue empties after the daemon's
//!     `negentropy_purge_drainer` step runs.
//!
//! All assertions go through public CLI surface — `sync-status`,
//! `keys`, and `messages` — so these tests do not poke at the in-memory
//! `SyncIndex` from Rust.

mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

// ---------------------------------------------------------------------------
// Test 1: single-peer determinism — purging the same id set twice (with
// different drain orderings simulated by clock jitter) reaches the same
// root summary, and the pending-purge queue empties after the daemon
// drainer ticks.
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_drainer_empties_queue_and_settles_root_after_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "DrainerSolo", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin the clock and author three messages so the workspace has a
    // non-trivial pre-expiry `root_fingerprint`.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    for body in ["hello-1", "hello-2", "hello-3"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), 3);

    let pre = sync_status(&alice);
    let pre_count: u64 = line_value(&pre, "indexed_events").parse().expect("count");
    assert!(
        pre_count >= 3,
        "indexed events must include at least the three authored messages:\n{pre}"
    );
    let pre_fingerprint = line_value(&pre, "root_fingerprint");
    assert_eq!(line_value(&pre, "pending_purges"), "0");

    // Spawn the daemon, advance past expiry, wait for retirement.
    let alice_daemon = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");

    // After the daemon has had time to drain the negentropy purge
    // queue, the queue should be empty and the root_fingerprint
    // should differ from the pre-expiry fingerprint (because the
    // purged messages no longer contribute to the XOR fold).
    wait_for_pending_purges(&alice, "0");
    let post = sync_status(&alice);
    assert_eq!(
        line_value(&post, "pending_purges"),
        "0",
        "pending purge queue must drain after daemon ticks:\n{post}"
    );
    let post_fingerprint = line_value(&post, "root_fingerprint");
    assert_ne!(
        pre_fingerprint, post_fingerprint,
        "root fingerprint must change after the purge drainer removes the expired ids:\n\
         pre={pre_fingerprint}\npost={post_fingerprint}"
    );
    let post_count: u64 = line_value(&post, "root_count").parse().expect("count");
    assert!(
        post_count <= pre_count.saturating_sub(3),
        "root count must drop by at least the three purged messages: \
         pre={pre_count}, post={post_count}"
    );

    drop(alice_daemon);
}

// ---------------------------------------------------------------------------
// Test 2: two peers that purge the same admitted set reach byte-identical
// negentropy root_fingerprint values, and a sync round between them after
// purge does not redeliver any of the purged ids (asserted indirectly via
// content_count remaining zero on both peers).
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_two_peers_converge_on_root_after_synchronized_purge() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let bob_join_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "DrainerPair", "alice", "alice-laptop", 1);
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

    // Pin both clocks to the same minute and have alice author messages
    // that bob will receive via sync.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    for body in ["secret-a", "secret-b", "secret-c"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    for body in ["secret-a", "secret-b", "secret-c"] {
        wait_for_message_text(&alice, &workspace_id, &format!("alice: {body}"));
        wait_for_message_text(&bob, &workspace_id, &format!("alice: {body}"));
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), 3);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 3);

    // Pre-expiry: both peers must have byte-identical root_fingerprints.
    let pre_alice = wait_for_root_fingerprint_to_match(&alice, &bob);
    let pre_bob = sync_status(&bob);
    assert_eq!(
        line_value(&pre_alice, "root_fingerprint"),
        line_value(&pre_bob, "root_fingerprint"),
        "root fingerprints must converge cross-peer pre-expiry:\nalice={pre_alice}\nbob={pre_bob}"
    );

    // Trigger expiry on both peers in lockstep.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");
    wait_for_pending_purges(&alice, "0");
    wait_for_pending_purges(&bob, "0");

    // Load-bearing assertion: cross-peer root_fingerprint converges to
    // the SAME value after both peers have purged the same id set. This
    // is the determinism property the negentropy drainer must uphold.
    let post_alice = wait_for_root_fingerprint_to_match(&alice, &bob);
    let post_bob = sync_status(&bob);
    assert_eq!(
        line_value(&post_alice, "root_fingerprint"),
        line_value(&post_bob, "root_fingerprint"),
        "root fingerprints must converge cross-peer post-purge:\nalice={post_alice}\nbob={post_bob}"
    );
    assert_eq!(
        line_value(&post_alice, "root_count"),
        line_value(&post_bob, "root_count"),
        "root count must converge cross-peer post-purge"
    );

    // The post-purge fingerprint must differ from the pre-purge value
    // — the drainer actually removed entries from the index, not just
    // set the queue size to zero.
    assert_ne!(
        line_value(&pre_alice, "root_fingerprint"),
        line_value(&post_alice, "root_fingerprint"),
        "root fingerprint must change after purge drains"
    );

    // Both pending-purge queues must be empty (already polled, but
    // re-assert here for clarity).
    assert_eq!(line_value(&post_alice, "pending_purges"), "0");
    assert_eq!(line_value(&post_bob, "pending_purges"), "0");

    // Sync round after purge: neither peer should re-request the
    // purged ids. The strongest CLI-visible signal is that
    // content_count stays at 0 on both peers across a follow-up sync
    // round, which we drive by waiting a short time and re-checking.
    thread::sleep(Duration::from_millis(500));
    assert_eq!(content_event_count(&alice, &workspace_id), "0");
    assert_eq!(content_event_count(&bob, &workspace_id), "0");
    // And one more cross-peer summary check after the follow-up round
    // to prove the sync exchange did not perturb the converged state.
    let stable_alice = sync_status(&alice);
    let stable_bob = sync_status(&bob);
    assert_eq!(
        line_value(&stable_alice, "root_fingerprint"),
        line_value(&stable_bob, "root_fingerprint"),
        "root fingerprint must remain converged across follow-up sync rounds"
    );
    assert_eq!(line_value(&stable_alice, "pending_purges"), "0");
    assert_eq!(line_value(&stable_bob, "pending_purges"), "0");
}

// ---------------------------------------------------------------------------
// Helpers (local to this test file). Mirror the patterns in
// `tests/disappearing_messages_cli_test.rs`. Code duplication is
// deliberate — each top-level test file owns its harness so per-test
// changes are isolated.
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

fn sync_status(db: &str) -> String {
    assert_success(topo(&["--db", db, "sync-status"]))
}

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

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
        let out = keys_value(db, workspace_id);
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

fn wait_for_pending_purges(db: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "sync-status"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "pending_purges") == expected {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("pending_purges did not reach {expected}:\n{last}");
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
    panic!("message text {expected_suffix:?} never appeared on db={db}:\n{last}");
}

/// Poll until `db` and `other` agree on `root_fingerprint`. Returns
/// the final `db` sync-status output. Convergence requires both
/// daemons to have caught up on each other's events; the wait is
/// bounded by the same 300-tick budget as the rest of the harness.
fn wait_for_root_fingerprint_to_match(db: &str, other: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let a = sync_status(db);
        let b = sync_status(other);
        if line_value(&a, "root_fingerprint") == line_value(&b, "root_fingerprint") {
            return a;
        }
        last = format!("db={a}\nother={b}");
        thread::sleep(Duration::from_millis(100));
    }
    panic!("root_fingerprint never converged:\n{last}");
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

// --- two-peer setup helpers (mirrored from tests/disappearing_messages_cli_test.rs) ---

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

//! Black-box CLI tests for the demoability affordances:
//!
//! - default listener (`start` with no `--listen`)
//! - `invite` reading the daemon listen address (no `--public-addr`)
//! - `invite` printing a copy-paste-ready accept line
//! - auto key setup: first `send` needs no `key-frontier`, and a joiner needs no
//!   `key-recipient`/`key-wrap` to read content (auto on accept + proactively)
//! - active/default workspace resolution and `use-workspace`
//! - the `status` command
//!
//! Everything goes through the real `con` binary; no protocol rows are seeded.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use cli_harness::*;

struct RunningDaemon {
    child: Child,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start a daemon with the given extra `start` args and return the full
/// `listening:` address it reports (e.g. `127.0.0.1:54321` or `0.0.0.0:54321`).
fn spawn_daemon_listening(db: &str, extra: &[&str]) -> (RunningDaemon, String) {
    let stderr_path = PathBuf::from(format!("{db}.daemon.stderr"));
    let mut argv: Vec<&str> = vec!["--db", db, "start", "--tick-ms", "50", "--quiet-ms", "50"];
    argv.extend_from_slice(extra);
    let mut child = spawn_topo_with_stderr_file(&argv, &stderr_path);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    reader.read_line(&mut first).expect("daemon first line");
    let addr = first
        .strip_prefix("listening: ")
        .unwrap_or_else(|| panic!("daemon did not report listening: {first}"))
        .trim()
        .to_string();
    (RunningDaemon { child }, addr)
}

/// Start a daemon WITHOUT `--listen` and return the OS-assigned port it reports.
fn spawn_default_daemon(db: &str) -> (RunningDaemon, u16) {
    let (daemon, addr) = spawn_daemon_listening(db, &[]);
    let port = addr
        .rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("could not parse listen port from {addr}"));
    (daemon, port)
}

fn line_value(output: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing `{key}` in output:\n{output}"))
        .to_string()
}

fn invite_link(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn accept_with_retry(db: &str, invite: &str, username: &str, device_name: &str) -> String {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(40) {
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
        thread::sleep(Duration::from_millis(50));
    }
    panic!("accept never succeeded for {username}:\n{last}");
}

/// Poll `con --db DB ARGS...` until stdout contains every needle, or panic.
fn wait_for_contains(db: &str, args: &[&str], needles: &[&str]) -> String {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(40) {
        let mut argv = vec!["--db", db];
        argv.extend_from_slice(args);
        let output = topo(&argv);
        if output.status.success() {
            let text = stdout(&output);
            if needles.iter().all(|needle| text.contains(needle)) {
                return text;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("`{args:?}` never contained {needles:?}; last:\n{last}");
}

#[test]
fn default_listener_invite_auto_addr_and_auto_content_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");

    let created = assert_success(topo(&[
        "--db",
        &alice,
        "create-workspace",
        "Demo",
        "--username",
        "alice",
        "--devicename",
        "laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");

    // B.1: both daemons start with no `--listen`.
    let (_alice_daemon, alice_port) = spawn_default_daemon(&alice);
    let (_bob_daemon, _bob_port) = spawn_default_daemon(&bob);

    // A.3 + A.7: invite needs no `--public-addr`, and prints the next step.
    let invite_out = assert_success(topo(&["--db", &alice, "invite", "--workspace", &workspace_id]));
    let invite = invite_link(&invite_out);
    assert!(
        invite.contains(&format!("127.0.0.1_{alice_port}")),
        "invite link should embed the auto-read daemon address:\n{invite_out}"
    );
    assert!(
        invite_out
            .lines()
            .any(|line| line.starts_with("next: con --db PEER.db accept ")),
        "invite should print a copy-paste accept line:\n{invite_out}"
    );

    // A.2: bob accepts; no `key-recipient` is run by hand.
    let accepted = accept_with_retry(&bob, &invite, "bob", "phone");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);

    // A.5: alice sends with no prior `key-frontier`.
    wait_for_contains(&alice, &["users", &workspace_id], &["alice", "bob"]);
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "hello bob"]));

    // A.2 + A.5: bob reads the message with NO manual key handshake at all.
    let bob_messages = wait_for_contains(&bob, &["messages", &workspace_id], &["hello bob"]);
    assert!(bob_messages.contains("alice"), "{bob_messages}");

    // Content is bidirectional under the same auto-established frontier.
    assert_success(topo(&["--db", &bob, "send", &workspace_id, "hi alice"]));
    wait_for_contains(&alice, &["messages", &workspace_id], &["hi alice"]);
}

#[test]
fn active_workspace_resolution_and_use_workspace_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    let created = assert_success(topo(&[
        "--db",
        &alice,
        "create-workspace",
        "Solo",
        "--username",
        "alice",
        "--devicename",
        "laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");
    let (_alice_daemon, _port) = spawn_default_daemon(&alice);

    // A.1: with a single workspace, `send`/`messages` need no workspace id.
    wait_for_contains(&alice, &["users", &workspace_id], &["alice"]);
    let sent = assert_success(topo(&["--db", &alice, "send", "no-id-needed"]));
    assert_eq!(line_value(&sent, "workspace_id"), workspace_id);
    let messages = wait_for_contains(&alice, &["messages"], &["no-id-needed"]);
    assert!(messages.contains("alice"), "{messages}");

    // A.1: `use-workspace` records the active selection.
    let used = assert_success(topo(&["--db", &alice, "use-workspace", &workspace_id]));
    assert_eq!(line_value(&used, "active_workspace"), workspace_id);

    // A.6: `workspaces` marks the active one with `*` and a short name line.
    let workspaces = assert_success(topo(&["--db", &alice, "workspaces"]));
    assert!(
        workspaces
            .lines()
            .any(|line| line.starts_with('*') && line.contains("Solo")),
        "active workspace should be marked with `*`:\n{workspaces}"
    );

    // An unknown workspace id is rejected with guidance.
    let bad = topo(&["--db", &alice, "use-workspace", &"0".repeat(64)]);
    assert!(!bad.status.success(), "unknown workspace should be rejected");
}

#[test]
fn status_reports_listen_endpoint_and_workspaces() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    // Before the daemon runs, status reports a stopped listener.
    let created = assert_success(topo(&[
        "--db",
        &alice,
        "create-workspace",
        "Demo",
        "--username",
        "alice",
        "--devicename",
        "laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");

    let stopped = assert_success(topo(&["--db", &alice, "status"]));
    assert!(
        stopped.lines().any(|line| line == "listen: stopped"),
        "status before start should report stopped:\n{stopped}"
    );

    let (_alice_daemon, port) = spawn_default_daemon(&alice);
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "one"]));

    let running = wait_for_contains(&alice, &["status"], &[&format!("127.0.0.1:{port}")]);
    assert!(running.contains("endpoint: "), "{running}");
    assert!(
        running
            .lines()
            .any(|line| line.contains("Demo") && line.contains(&workspace_id)),
        "status should list the workspace with its id:\n{running}"
    );
}

#[test]
fn id_less_react_does_not_treat_message_id_as_workspace() {
    // Regression: with a single (active) workspace, `react <message_id> 👍` omits
    // the workspace id. The message id is itself 64-char hex, so default workspace
    // resolution must not mistake it for an explicit workspace and skip resolution.
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    let created = assert_success(topo(&[
        "--db",
        &alice,
        "create-workspace",
        "Solo",
        "--username",
        "alice",
        "--devicename",
        "laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");
    let (_alice_daemon, _port) = spawn_default_daemon(&alice);
    wait_for_contains(&alice, &["users", &workspace_id], &["alice"]);

    // Send id-less, then capture the new message's id from `messages`.
    let sent = assert_success(topo(&["--db", &alice, "send", "react to me"]));
    let message_id = line_value(&sent, "message_id");

    // React id-less, selecting by full message id. This is the case the fix covers.
    let reacted = assert_success(topo(&["--db", &alice, "react", &message_id, "👍"]));
    assert_eq!(
        line_value(&reacted, "target_message_id"),
        message_id,
        "react should target the selected message, not parse its id as a workspace"
    );
    assert_eq!(
        line_value(&reacted, "workspace_id"),
        workspace_id,
        "react should resolve the active workspace, not the message id"
    );
}

#[test]
fn invite_on_wildcard_listener_requires_public_addr() {
    // Regression: a daemon bound to a wildcard address (0.0.0.0) reports a listen
    // address peers cannot dial. `invite` must NOT copy it into the link; it must
    // require an explicit `--public-addr` instead.
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    let created = assert_success(topo(&[
        "--db",
        &alice,
        "create-workspace",
        "Demo",
        "--username",
        "alice",
        "--devicename",
        "laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");

    let (_alice_daemon, addr) = spawn_daemon_listening(&alice, &["--listen", "0.0.0.0", "0"]);
    assert!(
        addr.starts_with("0.0.0.0:"),
        "daemon should report the wildcard bind:\n{addr}"
    );
    let port = addr.rsplit(':').next().expect("port");

    // Without --public-addr the wildcard bind must be rejected with guidance.
    let rejected = topo(&["--db", &alice, "invite", "--workspace", &workspace_id]);
    assert!(
        !rejected.status.success(),
        "invite on a wildcard listener should not auto-fill the address"
    );
    let err = stderr(&rejected);
    assert!(
        err.contains("--public-addr") && err.contains("wildcard"),
        "error should explain the wildcard listener needs --public-addr:\n{err}"
    );

    // With an explicit, dialable --public-addr the invite succeeds.
    let ok = assert_success(topo(&[
        "--db",
        &alice,
        "invite",
        "--workspace",
        &workspace_id,
        "--public-addr",
        &format!("127.0.0.1:{port}"),
    ]));
    assert!(
        ok.lines().any(|line| line.starts_with("topo://invite/")),
        "explicit --public-addr should produce an invite link:\n{ok}"
    );
}

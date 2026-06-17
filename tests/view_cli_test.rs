//! Black-box CLI tests for the cross-module `view` rendering command.
//!
//! Setup deliberately goes through the real `topo` binary: workspace creation,
//! content key derivation, message/reaction/file send. These tests must not
//! install identity graphs or content rows through test-only hooks; the `view`
//! rendering boundary is the invariant under test.

mod cli_harness;

use std::fs;
use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;

#[test]
fn cli_view_renders_sidebar_messages_reactions_files() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Activism", "alice", "laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    assert_success(topo(&["--db", &db, "send", &workspace_id, "hey bob"]));
    wait_for_messages_count(&db, &workspace_id, "1");
    assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_id,
        "second message",
    ]));
    wait_for_messages_count(&db, &workspace_id, "2");
    assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "+1"]));
    wait_for_view_contains(&db, &workspace_id, "+1 alice");

    let payload = b"hello world".to_vec();
    let in_path = tmp.path().join("payload.txt");
    fs::write(&in_path, &payload).expect("write input");
    assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("path utf-8"),
    ]));
    wait_for_view_contains(&db, &workspace_id, "payload.txt");

    let view = assert_success(topo(&["--db", &db, "view", &workspace_id]));

    // Sidebar must surface the local endpoint identity, the workspace name,
    // and the local user/device row.
    assert!(view.contains("IDENTITY:"), "missing IDENTITY:\n{view}");
    assert!(
        view.contains("endpoint_id: "),
        "missing endpoint_id line:\n{view}"
    );
    assert!(
        view.contains("signing_public_key: "),
        "missing signing_public_key line:\n{view}"
    );
    assert!(
        view.contains("WORKSPACE:\n  Activism"),
        "missing workspace name block:\n{view}"
    );
    assert!(view.contains("USERS:"), "missing USERS: header:\n{view}");
    assert!(
        view.contains("alice/laptop (you)"),
        "missing local user/device row:\n{view}"
    );

    // The 40-char divider must be present byte-for-byte.
    let divider = "\u{2500}".repeat(40);
    assert!(view.contains(&divider), "missing divider line:\n{view}");

    // Author block + numbered messages.
    assert!(
        view.contains("    alice ["),
        "missing author header:\n{view}"
    );
    assert!(
        view.contains("      1. hey bob"),
        "missing first message:\n{view}"
    );
    assert!(
        view.contains("      2. second message"),
        "missing second message:\n{view}"
    );
    assert!(
        view.contains("      3. see attached"),
        "missing send-file message:\n{view}"
    );

    // Reaction row: emoji followed by the reacting user.
    assert!(
        view.contains("         +1 alice"),
        "missing reaction row:\n{view}"
    );

    // File row: complete checkmark + filename + byte size.
    assert!(
        view.contains("\u{2714}  payload.txt (11 B)"),
        "missing file row:\n{view}"
    );
}

#[test]
fn cli_view_with_no_workspace_argument_picks_single_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Solo", "alice", "laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    assert_success(topo(&["--db", &db, "send", &workspace_id, "first"]));
    wait_for_messages_count(&db, &workspace_id, "1");

    let view = assert_success(topo(&["--db", &db, "view"]));

    assert!(
        view.contains("WORKSPACE:\n  Solo"),
        "no-arg view did not pick the single workspace:\n{view}"
    );
    assert!(
        view.contains("alice/laptop (you)"),
        "no-arg view did not surface local user:\n{view}"
    );
    assert!(
        view.contains("      1. first"),
        "no-arg view did not surface message:\n{view}"
    );
}

#[test]
fn cli_view_requires_argument_when_multiple_workspaces() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let one = create_workspace(&db, "WorkspaceOne", "alice", "laptop");
    let _two = create_workspace(&db, "WorkspaceTwo", "alice", "laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &one);
    wait_for_workspaces_count(&db, "2");

    let output = topo(&["--db", &db, "view"]);
    assert!(
        !output.status.success(),
        "view should fail without workspace selection: stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let err = stderr(&output);
    assert!(
        err.contains("select a workspace") && err.contains("WORKSPACE_ID_HEX"),
        "error message should ask for a workspace argument: {err}"
    );
}

#[test]
fn cli_view_with_explicit_workspace_argument_renders_that_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let one = create_workspace(&db, "WorkspaceOne", "alice", "laptop");
    let two = create_workspace(&db, "WorkspaceTwo", "alice", "laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &one);
    create_local_content_key(&db, &two);

    assert_success(topo(&["--db", &db, "send", &one, "in one"]));
    assert_success(topo(&["--db", &db, "send", &two, "in two"]));
    wait_for_messages_count(&db, &one, "1");
    wait_for_messages_count(&db, &two, "1");

    let view_one = assert_success(topo(&["--db", &db, "view", &one]));
    assert!(
        view_one.contains("WORKSPACE:\n  WorkspaceOne"),
        "expected WorkspaceOne header:\n{view_one}"
    );
    assert!(view_one.contains("      1. in one"), "{view_one}");
    assert!(!view_one.contains("in two"), "{view_one}");

    let view_two = assert_success(topo(&["--db", &db, "view", &two]));
    assert!(
        view_two.contains("WORKSPACE:\n  WorkspaceTwo"),
        "expected WorkspaceTwo header:\n{view_two}"
    );
    assert!(view_two.contains("      1. in two"), "{view_two}");
    assert!(!view_two.contains("in one"), "{view_two}");
}

#[test]
fn cli_view_collapses_consecutive_messages_from_same_author() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Activism", "alice", "laptop");
    let bob_join_port = free_port();
    let _alice_daemon = spawn_daemon(&alice, bob_join_port);
    let _bob_daemon = spawn_daemon(&bob, free_port());
    create_local_content_key(&alice, &workspace_id);
    join_workspace(&alice, &bob, &workspace_id, bob_join_port, "bob", "phone");

    // Alice sends two consecutive messages. Both should appear under one
    // author header on her local view.
    assert_success(topo(&[
        "--db",
        &alice,
        "send",
        &workspace_id,
        "first by alice",
    ]));
    assert_success(topo(&[
        "--db",
        &alice,
        "send",
        &workspace_id,
        "second by alice",
    ]));
    wait_for_messages_count(&alice, &workspace_id, "2");

    let view = assert_success(topo(&["--db", &alice, "view", &workspace_id]));
    let alice_header_count = view.matches("    alice [").count();
    assert_eq!(
        alice_header_count, 1,
        "expected one alice author header for two consecutive messages:\n{view}"
    );
    // Both messages should appear under the single Alice header; message
    // ordering is not part of this grouping invariant.
    assert!(
        view.contains("first by alice"),
        "missing first message:\n{view}"
    );
    assert!(
        view.contains("second by alice"),
        "missing second message:\n{view}"
    );
    // Both bob and alice should appear in the USERS list.
    assert!(view.contains("alice/laptop (you)"), "{view}");
    assert!(view.contains("bob/phone"), "{view}");
}

// --------------------------------------------------------------------------
// Helpers (mirror the structure from content_cli_test.rs/auth_cli_test.rs)
// --------------------------------------------------------------------------

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
    let _daemon = spawn_daemon(db, free_port());
    wait_for_users_contains(db, &workspace_id, username);
    wait_for_identity_contains(db, "endpoint_role=device");
    workspace_id
}

fn join_workspace(
    host: &str,
    joiner: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let invite = workspace_invite_for_addr(host, workspace_id, port);
    let accepted = match try_accept_with_identity_retry(joiner, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => panic!("workspace invite accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    wait_for_local_workspace_join(joiner, workspace_id, username);
    wait_for_users_contains(host, workspace_id, username);
    wait_for_peers_contains(host, workspace_id, device_name);
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
    invite_link_from_output(&out)
}

fn wait_for_local_workspace_join(db: &str, workspace_id: &str, username: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let recipient = topo(&["--db", db, "key-recipient", workspace_id]);
        let users = topo(&["--db", db, "users", workspace_id]);
        if recipient.status.success() && users.status.success() {
            let users = stdout(&users);
            if users.contains(username) {
                return;
            }
            last = users;
        } else {
            last = format!(
                "key-recipient stderr:\n{}\nusers stderr:\n{}",
                stderr(&recipient),
                stderr(&users)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("workspace join never projected for {username}: {last}");
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

fn wait_for_peers_contains(db: &str, workspace_id: &str, device_name: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let peers = topo(&["--db", db, "peers", workspace_id]);
        if peers.status.success() {
            let peers = stdout(&peers);
            if peers.contains(device_name) {
                return;
            }
            last = peers;
        } else {
            last = stderr(&peers);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("peer device {device_name} never appeared in {db}: {last}");
}

fn wait_for_identity_contains(db: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "identity"]);
        if output.status.success() {
            let text = stdout(&output);
            if text.contains(expected) {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("identity never contained {expected}: {last}");
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
            let text = stdout(&output);
            if line_value(&text, key) == expected {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("keys {key} did not reach {expected}: {last}");
}

fn wait_for_messages_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "messages", workspace_id]);
        if output.status.success() {
            let text = stdout(&output);
            if line_value(&text, "messages") == expected {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("messages count did not reach {expected}: {last}");
}

fn wait_for_view_contains(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "view", workspace_id]);
        if output.status.success() {
            let text = stdout(&output);
            if text.contains(expected) {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("view never contained {expected}: {last}");
}

fn wait_for_workspaces_count(db: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "workspaces"]);
        if output.status.success() {
            let text = stdout(&output);
            if line_value(&text, "workspaces") == expected {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("workspaces count did not reach {expected}: {last}");
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
        if !last.contains("open tcp stream") && !last.contains("user invite was not received") {
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

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

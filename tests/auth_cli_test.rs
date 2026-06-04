//! Black-box CLI tests for auth key-material availability.
//!
//! Setup goes through the real `topo` binary: workspace creation, invite
//! listening, invite acceptance, connection learning, sync, key
//! publication, wrap creation, and automatic derivation. The tests intentionally
//! do not seed protocol rows or inspect private storage layout; the CLI boundary
//! is the invariant under test.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;

#[test]
fn cli_key_derive_reports_key_wrap_summary_only() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "derive-output.db");

    let out = assert_success(topo(&["--db", &db, "key-derive"]));

    assert_eq!(line_value(&out, "scanned_key_wraps"), "0");
    assert_eq!(line_value(&out, "derived_key_secrets"), "0");
    assert_eq!(line_value(&out, "failed_key_wraps"), "0");
    assert_eq!(out.lines().count(), 3, "{out}");
}

#[test]
fn cli_key_wrap_derives_access_for_proactive_recipients() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let workspace_id = create_workspace(&alice, "Keys", "alice", "alice-laptop");
    let alice_port = free_port();
    let bob_port = free_port();
    let carol_port = free_port();

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    let _carol_daemon = spawn_daemon(&carol, carol_port);
    join_workspace_on_daemons(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");
    join_workspace_on_daemons(
        &alice,
        &carol,
        &workspace_id,
        alice_port,
        "carol",
        "carol-tablet",
    );

    assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    assert_success(topo(&["--db", &carol, "key-recipient", &workspace_id]));

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &alice,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "yes"
    );

    let bob_access = wait_for_key_access(&bob, &workspace_id, &removal_frontier_id, "yes");
    assert_eq!(line_value(&bob_access, "access"), "yes");
    let carol_access = wait_for_key_access(&carol, &workspace_id, &removal_frontier_id, "yes");
    assert_eq!(line_value(&carol_access, "access"), "yes");
}

#[test]
fn cli_invite_server_syncs_but_cannot_be_a_key_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let server = temp_db(&tmp, "invite-server.db");
    let workspace_id = create_workspace(&alice, "Helper FS", "alice", "alice-laptop");
    let alice_port = free_port();
    let server_port = free_port();

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _server_daemon = spawn_daemon(&server, server_port);
    join_invite_server_on_daemons(&alice, &server, &workspace_id, alice_port, "relay");
    let server_identity = assert_success(topo(&["--db", &server, "identity"]));
    assert!(
        server_identity.contains("endpoint_role=invite-server"),
        "{server_identity}"
    );

    let denied = topo(&["--db", &server, "key-recipient", &workspace_id]);
    assert!(
        !denied.status.success(),
        "invite-server recipient key should be invalid\nstdout={}\nstderr={}",
        stdout(&denied),
        stderr(&denied)
    );
    assert!(
        stderr(&denied).contains("local endpoint role cannot receive key wraps"),
        "{}",
        stderr(&denied)
    );

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    assert_success(topo(&[
        "--db",
        &alice,
        "generate",
        &workspace_id,
        "2",
        "64",
    ]));
    wait_for_content_count(
        &server,
        &workspace_id,
        "2",
        &[("alice", alice.as_str()), ("server", server.as_str())],
    );

    thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &server,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );
}

#[test]
fn cli_recipient_rotation_keeps_new_content_working_and_rejects_retired_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&alice, "Fs Keys", "alice", "alice-laptop");

    let first_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let first_recipient_id = line_value(&first_recipient, "recipient_key_id");
    let first_frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let first_frontier_id = line_value(&first_frontier, "removal_frontier_id");
    let first_wrap = assert_success(topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &first_frontier_id,
        &first_recipient_id,
    ]));
    assert_eq!(
        line_value(&first_wrap, "recipient_key_id"),
        first_recipient_id
    );
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &alice,
                "key-access",
                &workspace_id,
                &first_frontier_id,
            ])),
            "access",
        ),
        "yes"
    );

    let rotated = assert_success(topo(&[
        "--db",
        &alice,
        "key-rotate-recipient",
        &workspace_id,
    ]));
    assert_eq!(line_value(&rotated, "superseded_recipient_keys"), "1");
    assert!(
        !rotated.contains("old_active_recipient_keys:")
            && !rotated.contains("tombstoned_recipient_keys:"),
        "rotation output should use supersession vocabulary:\n{rotated}"
    );
    let new_recipient_key_id = line_value(&rotated, "recipient_key_id");

    let new_frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let new_frontier_id = line_value(&new_frontier, "removal_frontier_id");
    let old_wrap = topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &new_frontier_id,
        &first_recipient_id,
    ]);
    assert!(
        !old_wrap.status.success(),
        "retired recipient key should no longer be usable\nstdout={}\nstderr={}",
        stdout(&old_wrap),
        stderr(&old_wrap)
    );
    assert!(
        stderr(&old_wrap).contains("recipient key is missing"),
        "{}",
        stderr(&old_wrap)
    );

    let new_wrap = assert_success(topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &new_frontier_id,
        &new_recipient_key_id,
    ]));
    assert_eq!(
        line_value(&new_wrap, "recipient_key_id"),
        new_recipient_key_id
    );
    assert_success(topo(&[
        "--db",
        &alice,
        "send",
        &workspace_id,
        "after rotation",
    ]));
    let messages = messages_text(&alice, &workspace_id);
    assert_eq!(line_value(&messages, "messages"), "1");
    assert!(messages.contains("alice: after rotation"), "{messages}");
}

#[test]
fn cli_history_node_tombstone_rejects_derivation_from_retired_path() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&alice, "Fs Keys", "alice", "alice-laptop");

    assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let local_key_secret_id = line_value(&frontier, "local_key_secret_id");

    let root_node = assert_success(topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &local_key_secret_id,
        "0",
        "8",
    ]));
    let root_node_id = line_value(&root_node, "local_history_node_secret_id");

    let sibling = assert_success(topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &root_node_id,
        "4",
        "4",
        &root_node_id,
    ]));
    assert_eq!(line_value(&sibling, "tombstoned_node_id"), root_node_id);

    let from_retired_root = topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &root_node_id,
        "0",
        "4",
    ]);
    assert!(
        !from_retired_root.status.success(),
        "retired path node should not derive children\nstdout={}\nstderr={}",
        stdout(&from_retired_root),
        stderr(&from_retired_root)
    );
    assert!(
        stderr(&from_retired_root).contains("history node source fact is missing"),
        "{}",
        stderr(&from_retired_root)
    );
    // Remaining gap: no public CLI audit reports whether retired key-material
    // bytes are still recoverable from durable storage. This black-box test
    // can assert only the observable derivation refusal above.
}

#[test]
fn cli_peer_recipient_rotation_preserves_fresh_sharing_and_rejects_retired_wraps() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "FS Rotate", "alice", "alice-laptop");
    let alice_port = free_port();
    let bob_port = free_port();

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace_on_daemons(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");

    let recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let retired_recipient_key_id = line_value(&recipient, "recipient_key_id");
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let frontier_id = line_value(&frontier, "removal_frontier_id");
    let wrapped = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &frontier_id,
        &retired_recipient_key_id,
    );
    assert_eq!(
        line_value(&wrapped, "recipient_key_id"),
        retired_recipient_key_id
    );
    wait_for_key_access(&bob, &workspace_id, &frontier_id, "yes");

    let rotated = assert_success(topo(&["--db", &bob, "key-rotate-recipient", &workspace_id]));
    let superseded = line_value(&rotated, "superseded_recipient_keys")
        .parse::<u64>()
        .expect("parse superseded_recipient_keys");
    assert!(
        superseded >= 1,
        "rotation must retire at least one key:\n{rotated}"
    );
    let new_recipient_key_id = line_value(&rotated, "recipient_key_id");
    assert_ne!(new_recipient_key_id, retired_recipient_key_id);

    let new_frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let new_frontier_id = line_value(&new_frontier, "removal_frontier_id");
    let new_wrap = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &new_frontier_id,
        &new_recipient_key_id,
    );
    assert_eq!(
        line_value(&new_wrap, "recipient_key_id"),
        new_recipient_key_id
    );
    wait_for_key_access(&bob, &workspace_id, &new_frontier_id, "yes");

    let old_wrap = topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &new_frontier_id,
        &retired_recipient_key_id,
    ]);
    assert!(
        !old_wrap.status.success(),
        "alice must not be able to share new frontiers to bob's retired key after using bob's replacement key\nstdout={}\nstderr={}",
        stdout(&old_wrap),
        stderr(&old_wrap)
    );

    assert_success(topo(&[
        "--db",
        &alice,
        "send",
        &workspace_id,
        "after bob rotation",
    ]));
    wait_for_messages_contains(&bob, &workspace_id, "alice: after bob rotation");

    // Remaining gap: no public CLI audit proves retired recipient private keys
    // and old wraps are unrecoverable from durable storage after rotation. The
    // CLI-visible contract covered here is that retired recipient ids cannot
    // receive new wraps while the replacement key can still recover and display
    // new messages.
}

#[test]
fn cli_chop_purges_below_floor_messages_and_retains_above_floor_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id =
        create_workspace_with_ttl(&alice, "FS Chop Floor", "alice", "alice-laptop", 1000);

    let recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let retired_recipient_key_id = line_value(&recipient, "recipient_key_id");
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    assert_success(topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &removal_frontier_id,
        &retired_recipient_key_id,
    ]));

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

    let chop = assert_success(topo(&["--db", &alice, "chop-now", &workspace_id, "100"]));
    assert_eq!(line_value(&chop, "floor_minute"), "100");
    assert_eq!(
        line_value(&chop, "subtree_tombstones_written"),
        "1",
        "chop must retire the local frontier root at the floor boundary:\n{chop}"
    );
    let access_post = assert_success(topo(&[
        "--db",
        &alice,
        "key-access",
        &workspace_id,
        &removal_frontier_id,
    ]));
    assert_eq!(line_value(&access_post, "access"), "no");
    let keys_after_chop = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&keys_after_chop, "local_key_secrets"), "0");
    let post_messages = messages_text(&alice, &workspace_id);
    assert!(
        !post_messages.contains("alice: below floor"),
        "chop must purge below-floor opened message rows:\n{post_messages}"
    );
    assert!(
        post_messages.contains("alice: above floor"),
        "chop must not delete above-floor content rows:\n{post_messages}"
    );
    let count = assert_success(topo(&["--db", &alice, "content-count", &workspace_id]));
    assert_eq!(line_value(&count, "content_messages"), "1");

    let new_frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let new_frontier_id = line_value(&new_frontier, "removal_frontier_id");
    let retired_wrap = topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &new_frontier_id,
        &retired_recipient_key_id,
    ]);
    assert!(
        !retired_wrap.status.success(),
        "chop rotation must reject new wraps to the retired recipient\nstdout={}\nstderr={}",
        stdout(&retired_wrap),
        stderr(&retired_wrap)
    );
}

#[test]
fn cli_chop_revokes_frontier_rejects_old_wraps_and_allows_fresh_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&alice, "FS Chop Rotate", "alice", "alice-laptop");

    let recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let retired_recipient_key_id = line_value(&recipient, "recipient_key_id");
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    assert_success(topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &removal_frontier_id,
        &retired_recipient_key_id,
    ]));
    assert_success(topo(&["--db", &alice, "clock", "set", "3000000"]));
    let access_pre = assert_success(topo(&[
        "--db",
        &alice,
        "key-access",
        &workspace_id,
        &removal_frontier_id,
    ]));
    assert_eq!(line_value(&access_pre, "access"), "yes");
    assert_success(topo(&[
        "--db",
        &alice,
        "send",
        &workspace_id,
        "before chop",
    ]));
    assert!(messages_text(&alice, &workspace_id).contains("alice: before chop"));

    let chop = assert_success(topo(&["--db", &alice, "chop-now", &workspace_id, "100"]));
    assert_eq!(line_value(&chop, "floor_minute"), "100");
    let subtree: u64 = line_value(&chop, "subtree_tombstones_written")
        .parse()
        .expect("parse subtree");
    let boundary: u64 = line_value(&chop, "boundary_descend_tombstones_written")
        .parse()
        .expect("parse boundary");
    assert!(
        subtree + boundary > 0,
        "chop with non-zero floor must produce at least one tombstone:\n{chop}"
    );

    let access_post = assert_success(topo(&[
        "--db",
        &alice,
        "key-access",
        &workspace_id,
        &removal_frontier_id,
    ]));
    assert_eq!(
        line_value(&access_post, "access"),
        "no",
        "chop must wipe F's row"
    );
    let keys_after_chop = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(
        line_value(&keys_after_chop, "local_key_secrets"),
        "0",
        "chop must purge retired local key-secret fact bytes:\n{keys_after_chop}"
    );
    let post_messages = messages_text(&alice, &workspace_id);
    assert!(
        !post_messages.contains("alice: before chop"),
        "chop must purge below-floor opened message rows:\n{post_messages}"
    );
    let count_after_chop = assert_success(topo(&["--db", &alice, "content-count", &workspace_id]));
    assert_eq!(line_value(&count_after_chop, "content_messages"), "0");

    let new_frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let new_frontier_id = line_value(&new_frontier, "removal_frontier_id");
    let old_wrap = topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &new_frontier_id,
        &retired_recipient_key_id,
    ]);
    assert!(
        !old_wrap.status.success(),
        "chop must retire the recipient key that wrapped the deleted frontier\nstdout={}\nstderr={}",
        stdout(&old_wrap),
        stderr(&old_wrap)
    );
    assert_success(topo(&["--db", &alice, "clock", "set", "7200000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "after chop"]));
    let fresh_messages = messages_text(&alice, &workspace_id);
    assert!(
        fresh_messages.contains("alice: after chop"),
        "{fresh_messages}"
    );
    assert!(
        !fresh_messages.contains("alice: before chop"),
        "fresh authoring must not resurrect purged below-floor content:\n{fresh_messages}"
    );

    let _: u64 = line_value(&chop, "purged_secret_bytes")
        .parse()
        .expect("parse purged_secret_bytes");
    let _: u64 = line_value(&chop, "subsumed_message_tombstones_gcd")
        .parse()
        .expect("parse subsumed_message_tombstones_gcd");
    let _: u64 = line_value(&chop, "subsumed_leaf_tombstones_gcd")
        .parse()
        .expect("parse subsumed_leaf_tombstones_gcd");

    // Remaining gap: this black-box test proves the CLI rows and root access are
    // gone. A deeper cryptographic audit should additionally prove no retained
    // path node or key wrap can open the below-floor coordinate.
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

fn join_workspace_on_daemons(
    host: &str,
    joiner: &str,
    workspace_id: &str,
    host_port: u16,
    username: &str,
    device_name: &str,
) {
    let invite = workspace_invite_for_addr(host, workspace_id, host_port);
    let accepted = try_accept_with_identity_retry(joiner, &invite, username, device_name)
        .unwrap_or_else(|err| panic!("workspace invite accept failed: {err}"));
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    wait_for_local_workspace_join(joiner, workspace_id, username);
    wait_for_users_contains(host, workspace_id, username);
}

fn join_invite_server_on_daemons(
    host: &str,
    server: &str,
    workspace_id: &str,
    host_port: u16,
    device_name: &str,
) {
    let invite = invite_server_for_addr(host, workspace_id, host_port);
    let accepted = try_accept_invite_server_with_retry(server, &invite, device_name)
        .unwrap_or_else(|err| panic!("invite-server accept failed: {err}"));
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    assert_eq!(line_value(&accepted, "endpoint_role"), "invite-server");
    wait_for_identity_contains(server, "endpoint_role=invite-server");
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

fn invite_server_for_addr(db: &str, workspace_id: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&[
        "--db",
        db,
        "invite-server",
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

fn try_accept_invite_server_with_retry(
    db: &str,
    invite: &str,
    device_name: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept-invite-server",
            invite,
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
    let stderr_path = daemon_stderr_path(db);
    let mut child = spawn_topo_with_stderr_file(
        &[
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
        ],
        &stderr_path,
    );
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

fn wait_for_key_access(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    expected: &str,
) -> String {
    let mut last = String::new();
    for _ in 0..600 {
        let output = topo(&["--db", db, "key-access", workspace_id, removal_frontier_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "access") == expected {
                return out;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key access did not reach {expected}: {last}");
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

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

fn wait_for_messages_contains(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "messages", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if out.contains(expected) {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("messages never contained `{expected}`: {last}");
}

fn wait_for_content_count(db: &str, workspace_id: &str, expected: &str, daemons: &[(&str, &str)]) {
    let output = topo(&[
        "--db",
        db,
        "assert",
        "eventually",
        "content-count",
        workspace_id,
        "content_messages",
        "eq",
        expected,
        "--timeout-ms",
        "30000",
        "--poll-ms",
        "100",
    ]);
    assert!(
        output.status.success(),
        "content count did not reach {expected}\nstdout={}\nstderr={}\n\n{}",
        stdout(&output),
        stderr(&output),
        daemon_diagnostics_block(daemons)
    );
}

/// Invite bootstrap establishes membership, and afterwards a membership
/// `connect` reconnects the now-known peer without any invite material when the
/// caller supplies a current dial address.
#[test]
fn cli_membership_connect_reconnects_known_peer_without_invite() {
    let tmp = tempfile::tempdir().expect("tmp dir");
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Connect", "alice", "alice-laptop");
    let alice_port = free_port();
    let bob_port = free_port();

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    let daemons = [("alice", alice.as_str()), ("bob", bob.as_str())];

    // 1. Bootstrap join via invite; membership and a first message sync.
    join_workspace_on_daemons(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "first"]));
    wait_for_content_count(&bob, &workspace_id, "1", &daemons);

    // 2. connect to a never-seen endpoint errors: unknown peers need an invite.
    let unknown_endpoint = "ab".repeat(32);
    let alice_addr = format!("127.0.0.1:{alice_port}");
    let unknown = topo(&["--db", &bob, "connect", &unknown_endpoint, &alice_addr]);
    assert!(
        !unknown.status.success(),
        "connect to an unknown endpoint must error instead of inventing a connection:\nstdout={}\nstderr={}",
        stdout(&unknown),
        stderr(&unknown)
    );

    // 3. connect to the now-known peer resolves to a membership connection. bob
    // holds alice's endpoint_shared (synced during bootstrap), and the caller
    // supplies the current address — no invite material involved.
    let alice_identity = assert_success(topo(&["--db", &alice, "identity"]));
    let alice_endpoint = line_value(&alice_identity, "endpoint_id");
    let connect = assert_success(topo(&[
        "--db",
        &bob,
        "connect",
        &alice_endpoint,
        &alice_addr,
    ]));
    assert!(
        connect.contains("request_id="),
        "membership connect should report its request id:\n{connect}"
    );

    // 4. Content authored after the membership connect still syncs.
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "second"]));
    wait_for_content_count(&bob, &workspace_id, "2", &daemons);
}

//! Black-box CLI tests for content messages.
//!
//! Setup deliberately goes through the real `topo` binary: workspace creation,
//! daemon-served invite acceptance, connection learning, sync, and content
//! commands. These tests must not install identity graphs or content rows by
//! importing protocol/store internals.

mod cli_harness;

use std::fs;
use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;
use rusqlite::{params, Connection};
use topo::core::crypto;

#[test]
fn cli_send_then_messages_lists_authored_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let send1 = assert_success(topo(&["--db", &db, "send", &workspace_id, "first message"]));
    assert!(send1.contains("text: first message"), "{send1}");

    let send2 = assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_id,
        "second message",
    ]));
    assert!(send2.contains("text: second message"), "{send2}");

    wait_for_messages_count(&db, &workspace_id, "2");
    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&listing, "messages"), "2");
    assert!(listing.contains("alice: first message"), "{listing}");
    assert!(listing.contains("alice: second message"), "{listing}");
}

#[test]
fn cli_react_appears_in_messages_listing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    assert_success(topo(&["--db", &db, "send", &workspace_id, "hello"]));
    wait_for_messages_count(&db, &workspace_id, "1");
    let react = assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "+1"]));
    assert!(react.contains("emoji: +1"), "{react}");
    wait_for_messages_contains(&db, &workspace_id, "reactions: +1");

    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(listing.contains("reactions: +1"), "{listing}");
}

#[test]
fn cli_stores_reactions_and_files_as_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    assert_success(topo(&["--db", &db, "send", &workspace_id, "hello"]));
    wait_for_messages_count(&db, &workspace_id, "1");
    assert_success(topo(&[
        "--db",
        &db,
        "react",
        &workspace_id,
        "#1",
        "super-secret-emoji",
    ]));
    wait_for_messages_contains(&db, &workspace_id, "reactions: super-secret-emoji");

    let payload = b"clear file body secret".to_vec();
    let in_path = tmp.path().join("secret-name.txt");
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
    wait_for_files_count(&db, &workspace_id, "1");
    wait_for_messages_count(&db, &workspace_id, "2");

    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(
        listing.contains("reactions: super-secret-emoji"),
        "{listing}"
    );
    let saved = tmp.path().join("saved.txt");
    assert_success(topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        saved.to_str().expect("path utf-8"),
    ]));
    assert_eq!(fs::read(saved).expect("read saved"), payload);

    let conn = Connection::open(&db).expect("open db");
    let reaction_ciphertext: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM content_reactions WHERE deleted = 0 LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("reaction ciphertext");
    assert!(
        !blob_contains(&reaction_ciphertext, b"super-secret-emoji"),
        "reaction plaintext leaked into ciphertext"
    );

    let sealed_metadata: Vec<u8> = conn
        .query_row(
            "SELECT sealed_metadata FROM content_files WHERE deleted = 0 LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("file metadata");
    assert!(
        !blob_contains(&sealed_metadata, b"secret-name.txt"),
        "filename leaked into sealed metadata"
    );

    let slice_ciphertext: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM file_slice_rows LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("file slice ciphertext");
    assert_ne!(slice_ciphertext, payload, "file slice stored plaintext");
    assert!(
        !blob_contains(&slice_ciphertext, &payload),
        "file payload leaked into slice ciphertext"
    );
    let root_hash: Vec<u8> = conn
        .query_row(
            "SELECT root_hash FROM content_files WHERE deleted = 0 LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("file root hash");
    assert_ne!(
        root_hash,
        crypto::hash(&payload).to_vec(),
        "file root hash must commit to encrypted bytes, not plaintext"
    );
    assert_eq!(
        root_hash,
        crypto::hash(&slice_ciphertext).to_vec(),
        "single-slice file root hash must match stored encrypted blob"
    );
}

#[test]
fn cli_view_renders_sidebar_messages_reactions_files() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Activism", "alice", "laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    assert_success(topo(&["--db", &db, "send", &workspace_id, "hey bob"]));
    assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_id,
        "second message",
    ]));
    wait_for_messages_count(&db, &workspace_id, "2");
    assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "+1"]));
    wait_for_messages_contains(&db, &workspace_id, "reactions: +1");

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
    wait_for_files_count(&db, &workspace_id, "1");
    wait_for_messages_count(&db, &workspace_id, "3");

    let view = assert_success(topo(&["--db", &db, "view", &workspace_id]));

    // Invariant: the content-root view renders local identity, workspace, and
    // user/device sidebar facts from the same black-box CLI setup as content.
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

    let divider = "\u{2500}".repeat(40);
    assert!(view.contains(&divider), "missing divider line:\n{view}");

    assert!(
        view.contains("    alice ["),
        "missing author header:\n{view}"
    );
    assert!(view.contains("hey bob"), "missing first message:\n{view}");
    assert!(
        view.contains("second message"),
        "missing second message:\n{view}"
    );
    assert!(
        view.contains("see attached"),
        "missing send-file message:\n{view}"
    );
    assert!(
        view.contains("         +1 alice"),
        "missing reaction row:\n{view}"
    );
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

    // Invariant: the content-root view may omit WORKSPACE_ID only when the
    // local endpoint has exactly one joined workspace.
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
    let alice_port = free_port();
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, free_port());
    create_local_content_key(&alice, &workspace_id);

    join_workspace_on_daemons(&alice, &bob, &workspace_id, alice_port, "bob", "phone");

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
    assert!(
        view.contains("first by alice"),
        "missing first message:\n{view}"
    );
    assert!(
        view.contains("second by alice"),
        "missing second message:\n{view}"
    );
    assert!(view.contains("alice/laptop (you)"), "{view}");
    assert!(view.contains("bob/phone"), "{view}");
}

#[test]
fn cli_delete_message_removes_target_from_listing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    assert_success(topo(&["--db", &db, "send", &workspace_id, "regret"]));
    wait_for_messages_count(&db, &workspace_id, "1");
    assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "ack"]));
    wait_for_messages_contains(&db, &workspace_id, "reactions: ack");

    let before = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(!before.contains("(deleted)"), "{before}");

    let deleted = assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    assert!(deleted.contains("fact_id:"), "{deleted}");
    wait_for_messages_count(&db, &workspace_id, "0");

    let after = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&after, "messages"), "0");
    assert!(!after.contains("(deleted)"), "{after}");
    assert!(!after.contains("regret"), "{after}");
}

#[test]
fn cli_send_file_then_save_file_round_trips_bytes_through_real_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let payload: Vec<u8> = (0..8192u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("input.bin");
    fs::write(&in_path, &payload).expect("write input");

    let sent = assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("path utf-8"),
    ]));
    assert!(sent.contains("filename: input.bin"), "{sent}");
    assert_eq!(line_value(&sent, "blob_bytes"), "8192");
    let file_fact_id = line_value(&sent, "file_fact_id");
    wait_for_files_count(&db, &workspace_id, "1");
    wait_for_messages_contains(&db, &workspace_id, "file: input.bin");

    let files = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(files_total(&files), "1");
    assert!(files.contains("input.bin"), "{files}");
    // poc-7 listing format: complete files render with the heavy-check status.
    assert!(files.contains("\u{2714}"), "{files}");

    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(
        messages.contains("see attached") && messages.contains("file: input.bin"),
        "{messages}"
    );

    let out_path = tmp.path().join("out.bin");
    let saved = assert_success(topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        out_path.to_str().expect("path utf-8"),
    ]));
    assert_eq!(line_value(&saved, "filename"), "input.bin");
    assert_eq!(line_value(&saved, "bytes_written"), "8192");

    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back, payload);

    assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    wait_for_messages_count(&db, &workspace_id, "0");
    wait_for_files_count(&db, &workspace_id, "0");
    let messages_after_delete = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&messages_after_delete, "messages"), "0");
    let files_after_delete = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(files_total(&files_after_delete), "0");

    let hidden_save = topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        &file_fact_id,
        out_path.to_str().expect("path utf-8"),
    ]);
    assert!(
        !hidden_save.status.success(),
        "deleted parent message must hide direct file saves\nstdout={}\nstderr={}",
        stdout(&hidden_save),
        stderr(&hidden_save)
    );
}

#[test]
fn cli_save_file_rejects_root_hash_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("input.bin");
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
    wait_for_files_count(&db, &workspace_id, "1");

    let conn = Connection::open(&db).expect("open db");
    conn.execute(
        "UPDATE content_files SET root_hash = ?1 WHERE deleted = 0",
        params![vec![0x7fu8; crypto::HASH_BYTES]],
    )
    .expect("tamper root hash");

    let out_path = tmp.path().join("out.bin");
    let output = topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        out_path.to_str().expect("path utf-8"),
    ]);
    assert!(
        !output.status.success(),
        "save-file unexpectedly succeeded\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("file encrypted root hash mismatch"),
        "wrong error:\n{}",
        stderr(&output)
    );
    assert!(
        !out_path.exists(),
        "save-file wrote bytes after root mismatch"
    );
}

#[test]
fn cli_messages_and_reactions_sync_between_two_peers() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Shared", "alice", "alice-laptop");
    let alice_port = free_port();
    let bob_port = free_port();

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace_on_daemons(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    assert_success(topo(&["--db", &alice, "send", &workspace_id, "from alice"]));
    wait_for_messages_count(&alice, &workspace_id, "1");
    assert_success(topo(&[
        "--db",
        &alice,
        "react",
        &workspace_id,
        "#1",
        "seen",
    ]));

    wait_for_messages_count(&bob, &workspace_id, "1");
    wait_for_messages_contains(&bob, &workspace_id, "reactions: seen");
    let bob_listing = assert_success(topo(&["--db", &bob, "messages", &workspace_id]));
    assert_eq!(line_value(&bob_listing, "messages"), "1");
    assert!(bob_listing.contains("alice: from alice"), "{bob_listing}");
    assert!(bob_listing.contains("reactions: seen"), "{bob_listing}");
}

#[test]
fn cli_received_deletion_hides_message_after_processes_exit() {
    let sentinel = "received-delete-visible-sentinel-3a91";
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Shared", "alice", "alice-laptop");
    let alice_port = free_port();
    let bob_port = free_port();

    {
        let _alice_daemon = spawn_daemon(&alice, alice_port);
        let _bob_daemon = spawn_daemon(&bob, bob_port);
        join_workspace_on_daemons(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");
        grant_content_key_to_peer(&alice, &bob, &workspace_id);

        assert_success(topo(&["--db", &alice, "send", &workspace_id, sentinel]));

        // Bob receives the message before alice deletes; this proves the deletion
        // arrives via sync and not as a delete-before-message ordering quirk.
        wait_for_messages_count(&bob, &workspace_id, "1");
        wait_for_messages_contains(&bob, &workspace_id, sentinel);

        assert_success(topo(&[
            "--db",
            &alice,
            "delete-message",
            &workspace_id,
            "#1",
        ]));

        // Wait until bob's CLI-visible message listing reflects the deletion.
        wait_for_messages_count(&bob, &workspace_id, "0");
        wait_for_content_count(&bob, &workspace_id, "0");
    }

    // The sync processes are dropped here. A fresh CLI read should still show
    // that the deleted message bytes are absent.
    let bob_listing = assert_success(topo(&["--db", &bob, "messages", &workspace_id]));
    assert_eq!(line_value(&bob_listing, "messages"), "0");
    assert!(!bob_listing.contains(sentinel), "{bob_listing}");
    assert_eq!(content_message_count(&bob, &workspace_id), "0");
    // Remaining gap: there is no CLI-visible deletion-fact audit separate
    // from the persisted absence in `messages` and `content-count`.
}

#[test]
fn cli_send_file_syncs_bytes_to_peer_for_save() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Files", "alice", "alice-laptop");
    let alice_port = free_port();
    let bob_port = free_port();

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace_on_daemons(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("payload.bin");
    fs::write(&in_path, &payload).expect("write input");

    assert_success(topo(&[
        "--db",
        &alice,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("path"),
    ]));

    wait_for_files_count(&bob, &workspace_id, "1");
    let listing = assert_success(topo(&["--db", &bob, "files", &workspace_id]));
    assert_eq!(files_total(&listing), "1");
    let out_path = tmp.path().join("out.bin");
    let saved = wait_for_save_file(&bob, &workspace_id, "#1", out_path.to_str().expect("path"));
    assert_eq!(line_value(&saved, "filename"), "payload.bin");
    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back, payload);
}

/// Returns `Some((slices_received, total_slices))` if the listing contains a
/// row matching poc-7's format; useful for both partial and complete states.
fn parse_first_progress_row(listing: &str) -> Option<(u32, u32, bool)> {
    // Look for a row line: `  N. STATUS  filename (size[, NN%])`
    // We don't try to parse the size; we read off whether the row is the
    // hourglass (incomplete) form and, if so, the percentage suffix.
    for line in listing.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        // Detect status icon.
        if trimmed.contains("\u{2714}") {
            return Some((1, 1, true));
        }
        if trimmed.contains("\u{23f3}") {
            // Find ", NN%)" suffix; if missing, treat as 0/0.
            if let Some(pct_start) = trimmed.rfind(", ") {
                let after = &trimmed[pct_start + 2..];
                if let Some(pct_str) = after.strip_suffix("%)") {
                    if let Ok(pct) = pct_str.parse::<u32>() {
                        // We don't know absolute counts from the rendered row,
                        // but this carries enough signal to assert progress.
                        // For tests that need the exact counts, fall back to
                        // a CLI command that reports them directly.
                        return Some((pct, 100, false));
                    }
                }
            }
            return Some((0, 0, false));
        }
    }
    None
}

fn delete_verified_file_slices_from(db: &str, first_deleted_slice_index: u32) {
    let conn = Connection::open(db).expect("open db");
    conn.execute(
        "DELETE FROM file_slice_rows WHERE slice_index >= ?1",
        params![i64::from(first_deleted_slice_index)],
    )
    .expect("delete verified slice rows");
}

#[test]
fn cli_files_listing_counts_verified_slice_rows_as_progress() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Progress", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    // Four fixed 256 KiB slices. Delete two verified rows after projection so
    // the listing has a deterministic 50% partial state without racing sync.
    let payload: Vec<u8> = (0..(1024 * 1024u32)).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("big.bin");
    fs::write(&in_path, &payload).expect("write input");
    assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached big",
        "--file",
        in_path.to_str().expect("path"),
    ]));
    wait_for_files_count(&db, &workspace_id, "1");
    delete_verified_file_slices_from(&db, 2);

    let partial = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    let progress = parse_first_progress_row(&partial)
        .unwrap_or_else(|| panic!("no progress row recognized in:\n{partial}"));
    let (pct, _denom, complete) = progress;
    assert!(
        !complete,
        "partial listing reported as complete:\n{partial}"
    );
    assert_eq!(pct, 50, "{partial}");
    assert!(partial.contains("\u{23f3}"), "{partial}");
    assert!(partial.contains("%)"), "{partial}");
    assert!(
        partial.lines().any(|l| l == "FILES (1 total):"),
        "{partial}"
    );
}

#[test]
fn cli_save_file_rejects_incomplete_download() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Reject", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let payload: Vec<u8> = (0..(512 * 1024u32)).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("big.bin");
    fs::write(&in_path, &payload).expect("write input");
    assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached big",
        "--file",
        in_path.to_str().expect("path"),
    ]));
    wait_for_files_count(&db, &workspace_id, "1");
    delete_verified_file_slices_from(&db, 1);

    let out_path = tmp.path().join("out.bin");
    let output = topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        out_path.to_str().expect("path"),
    ]);
    assert!(
        !output.status.success(),
        "save-file unexpectedly succeeded:\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    let err = stderr(&output);
    assert!(
        err.contains("file incomplete: have 1/2 slices"),
        "save-file did not report incomplete; stderr was:\n{err}"
    );
}

#[test]
fn cli_save_file_assembles_slices_by_index() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Order", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    // 2 slices @ 256 KiB = 512 KiB. Vary the byte pattern by slice index so a
    // wrong-order assembly would fail the equality check, not just length.
    const SLICE_BYTES: usize = 256 * 1024;
    const NUM_SLICES: usize = 2;
    let mut payload = Vec::with_capacity(NUM_SLICES * SLICE_BYTES);
    for slice_idx in 0..NUM_SLICES as u8 {
        for offset in 0..SLICE_BYTES {
            // Pattern depends on (slice_idx, offset) so any reordered or
            // duplicated slice would corrupt the hash.
            payload.push(slice_idx.wrapping_add((offset % 251) as u8));
        }
    }
    let in_path = tmp.path().join("ordered.bin");
    fs::write(&in_path, &payload).expect("write input");

    assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached ordered",
        "--file",
        in_path.to_str().expect("path"),
    ]));
    wait_for_files_count(&db, &workspace_id, "1");
    rewrite_verified_file_slices_in_reverse(&db);

    let out_path = tmp.path().join("out.bin");
    let saved = assert_success(topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        out_path.to_str().expect("path"),
    ]));
    assert_eq!(line_value(&saved, "filename"), "ordered.bin");
    assert_eq!(
        line_value(&saved, "bytes_written"),
        format!("{}", payload.len())
    );

    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back.len(), payload.len(), "saved length differs");
    assert_eq!(read_back, payload, "saved bytes do not round-trip");
}

fn rewrite_verified_file_slices_in_reverse(db: &str) {
    let conn = Connection::open(db).expect("open db");
    let rows = {
        let mut stmt = conn
            .prepare(
                "SELECT workspace_id, file_id, slice_index, slice_fact_id, created_at_ms, ciphertext
                 FROM file_slice_rows
                 ORDER BY slice_index DESC",
            )
            .expect("select file slice rows");
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .expect("query slice rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect slice rows")
    };
    conn.execute("DELETE FROM file_slice_rows", [])
        .expect("delete slice rows");
    for (workspace_id, file_id, slice_index, slice_fact_id, created_at_ms, ciphertext) in rows {
        conn.execute(
            "INSERT INTO file_slice_rows
             (workspace_id, file_id, slice_index, slice_fact_id, created_at_ms, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                workspace_id,
                file_id,
                slice_index,
                slice_fact_id,
                created_at_ms,
                ciphertext
            ],
        )
        .expect("insert reversed slice row");
    }
}

#[test]
fn cli_files_listing_shows_zero_progress_when_only_descriptor_received() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Zero", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let payload: Vec<u8> = (0..(512 * 1024u32)).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("very_big.bin");
    fs::write(&in_path, &payload).expect("write input");
    assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached very big",
        "--file",
        in_path.to_str().expect("path"),
    ]));
    wait_for_files_count(&db, &workspace_id, "1");
    delete_verified_file_slices_from(&db, 0);

    let partial = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert!(
        partial.contains("\u{23f3}"),
        "expected hourglass status in:\n{partial}"
    );
    let progress = parse_first_progress_row(&partial).expect("progress row");
    assert!(
        !progress.2,
        "partial listing reported as complete:\n{partial}"
    );
    assert_eq!(progress.0, 0, "{partial}");

    let out_path = tmp.path().join("out.bin");
    let output = topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        out_path.to_str().expect("path"),
    ]);
    assert!(
        !output.status.success(),
        "save-file unexpectedly succeeded:\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    let err = stderr(&output);
    assert!(
        err.contains("file incomplete: have 0/2 slices"),
        "save-file did not report incomplete; stderr was:\n{err}"
    );
}

#[test]
fn cli_send_file_with_explicit_mime_round_trips_bytes() {
    let sentinel = "sentinel-fs-bytes-keep-this-unique-1234567890";

    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Sealed", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let in_path = tmp.path().join("input.bin");
    let mut payload = Vec::new();
    // Pad with non-sentinel bytes so the file is multi-slice-worthy.
    payload.extend(sentinel.as_bytes());
    payload.extend(std::iter::repeat_n(0xa5u8, 1024));
    fs::write(&in_path, &payload).expect("write input");

    let secret_filename = "secret-name-92e1f.bin";
    let secret_in_path = tmp.path().join(secret_filename);
    fs::write(&secret_in_path, &payload).expect("write secret named input");

    let sent = assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "subject does not leak filename",
        "--file",
        secret_in_path.to_str().expect("path"),
        "--mime",
        "application/x-secret-mime-3713",
    ]));
    assert!(
        sent.contains(&format!("filename: {}", secret_filename)),
        "{sent}"
    );
    assert_eq!(
        line_value(&sent, "blob_bytes"),
        format!("{}", payload.len())
    );
    wait_for_files_count(&db, &workspace_id, "1");

    let files = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(files_total(&files), "1");
    assert!(files.contains(secret_filename), "{files}");

    let out_path = tmp.path().join("saved-secret.bin");
    let saved = assert_success(topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        out_path.to_str().expect("path utf-8"),
    ]));
    assert_eq!(line_value(&saved, "filename"), secret_filename);
    assert_eq!(
        line_value(&saved, "bytes_written"),
        format!("{}", payload.len())
    );
    assert_eq!(fs::read(&out_path).expect("read saved file"), payload);

    // Remaining gap: no CLI-visible storage-secrecy check proves encrypted
    // file payload, filename, and MIME bytes are hidden at rest. This
    // black-box CLI test intentionally avoids scanning the SQLite file.
}

#[test]
fn cli_delete_message_hides_attached_file_and_rejects_save() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Purge", "alice", "alice-laptop");
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let in_path = tmp.path().join("input.bin");
    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    fs::write(&in_path, &payload).expect("write input");

    let sent = assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "delete me",
        "--file",
        in_path.to_str().expect("path"),
    ]));
    let file_fact_id = line_value(&sent, "file_fact_id");
    wait_for_files_count(&db, &workspace_id, "1");
    let files_before = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(files_total(&files_before), "1");

    assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    wait_for_files_count(&db, &workspace_id, "0");
    wait_for_messages_count(&db, &workspace_id, "0");

    let after_files = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(files_total(&after_files), "0");
    let after_messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&after_messages, "messages"), "0");
    assert_eq!(content_message_count(&db, &workspace_id), "0");

    let out_path = tmp.path().join("deleted.bin");
    let output = topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        &file_fact_id,
        out_path.to_str().expect("path"),
    ]);
    assert!(
        !output.status.success(),
        "deleted message should hide attached file saves\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    // The public purge signal is `content-count`: the deleted content-message,
    // file descriptor, and file-slice content rows are gone, while
    // `messages`/`files` and `save-file` cover the read-model behavior.
}

#[test]
fn cli_delete_message_hides_attached_file_on_peer_after_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "PeerPurge", "alice", "alice-laptop");
    let alice_port = free_port();
    let bob_port = free_port();

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace_on_daemons(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    let in_path = tmp.path().join("input.bin");
    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    fs::write(&in_path, &payload).expect("write input");

    let sent = assert_success(topo(&[
        "--db",
        &alice,
        "send-file",
        &workspace_id,
        "peer delete target",
        "--file",
        in_path.to_str().expect("path"),
    ]));
    let file_fact_id = line_value(&sent, "file_fact_id");
    sync_full_range_to_peer(&alice, &bob, &workspace_id);
    wait_for_files_count(&bob, &workspace_id, "1");

    assert_success(topo(&[
        "--db",
        &alice,
        "delete-message",
        &workspace_id,
        "#1",
    ]));
    sync_full_range_to_peer(&alice, &bob, &workspace_id);

    // Wait for bob's CLI-visible listings to reflect the synced deletion.
    wait_for_messages_count(&bob, &workspace_id, "0");
    wait_for_files_count(&bob, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");

    let out_path = tmp.path().join("deleted-peer.bin");
    let output = topo(&[
        "--db",
        &bob,
        "save-file",
        &workspace_id,
        &file_fact_id,
        out_path.to_str().expect("path"),
    ]);
    assert!(
        !output.status.success(),
        "deleted synced message should hide attached file saves on peer\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    // The public purge signal is `content-count`: bob has no remaining
    // message/file content rows for the synced deleted bytes.
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
    let workspace_id = line_value(&out, "workspace_id");
    let _daemon = spawn_daemon(db, free_port());
    wait_for_users_contains(db, &workspace_id, username, &[("db", db)]);
    wait_for_identity_contains(db, "endpoint_role=device");
    workspace_id
}

fn create_local_content_key(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "key-frontier", workspace_id]));
    wait_for_keys_value(db, workspace_id, "local_key_secrets", "1");
    wait_for_keys_value(db, workspace_id, "removal_frontiers", "1");
    out
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
    wait_for_users_contains(
        host,
        workspace_id,
        username,
        &[("host", host), ("joiner", joiner)],
    );
    wait_for_peers_contains(
        host,
        workspace_id,
        device_name,
        &[("host", host), ("joiner", joiner)],
    );
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

fn wait_for_users_contains(db: &str, workspace_id: &str, username: &str, daemons: &[(&str, &str)]) {
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
    panic!(
        "user {username} never appeared in {db}: {last}\n\n{}",
        daemon_diagnostics_block(daemons)
    );
}

fn wait_for_peers_contains(
    db: &str,
    workspace_id: &str,
    device_name: &str,
    daemons: &[(&str, &str)],
) {
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
    panic!(
        "peer device {device_name} never appeared in {db}: {last}\n\n{}",
        daemon_diagnostics_block(daemons)
    );
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

fn grant_content_key_to_peer(alice: &str, peer: &str, workspace_id: &str) {
    let recipient = assert_success(topo(&["--db", peer, "key-recipient", workspace_id]));
    let recipient_key_id = line_value(&recipient, "recipient_key_id");
    let frontier = create_local_content_key(alice, workspace_id);
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let wrapped = key_wrap_with_retry(alice, workspace_id, &removal_frontier_id, &recipient_key_id);
    assert_eq!(line_value(&wrapped, "recipient_key_id"), recipient_key_id);
    wait_for_key_access(peer, workspace_id, &removal_frontier_id, "yes");
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

fn wait_for_key_access(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    expected: &str,
) -> String {
    let mut last = String::new();
    for _ in 0..300 {
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

fn sync_full_range_to_peer(sender: &str, receiver: &str, workspace_id: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", sender, "sync", "all"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "mode") == "all" {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("sync all setting did not become visible in {sender} before syncing {workspace_id} to {receiver}: {last}");
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn wait_for_messages_count(db: &str, workspace_id: &str, expected: &str) {
    wait_for_count(db, "messages", workspace_id, "messages", expected);
}

fn content_message_count(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "content-count", workspace_id]));
    line_value(&out, "content_messages")
}

fn wait_for_content_count(db: &str, workspace_id: &str, expected: &str) {
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
        daemon_diagnostics_block(&[("db", db)])
    );
}

fn wait_for_files_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "files", workspace_id]));
        if files_total(&out) == expected {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("files count did not reach {expected}; last output:\n{last}");
}

/// Parse the `FILES (N total):` header from a `files` listing as a string.
/// Matches poc-7's listing header.
fn files_total(output: &str) -> String {
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("FILES (") {
            if let Some(num) = rest.split_once(' ').map(|(n, _)| n) {
                return num.to_string();
            }
        }
    }
    panic!("missing `FILES (N total):` header in output:\n{output}");
}

fn wait_for_messages_contains(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "messages", workspace_id]));
        if out.contains(expected) {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "messages never contained `{expected}`; last output:\n{last}\n\n{}",
        daemon_diagnostics_block(&[("db", db)])
    );
}

fn wait_for_save_file(db: &str, workspace_id: &str, selector: &str, out_path: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "save-file", workspace_id, selector, out_path]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("save-file never succeeded; last stderr:\n{last}");
}

fn wait_for_count(db: &str, command: &str, workspace_id: &str, key: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, command, workspace_id]));
        if line_value(&out, key) == expected {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "{command} count did not reach {expected}; last output:\n{last}\n\n{}",
        daemon_diagnostics_block(&[("db", db)])
    );
}

fn blob_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

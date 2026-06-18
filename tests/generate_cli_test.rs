mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;
use rusqlite::{params, Connection};

#[test]
fn generate_cli_uses_real_store_and_reports_applied_facts() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "generate.db");
    let workspace_id = create_workspace(&db);
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);
    let before_status = assert_success(topo(&["--db", &db, "count"]));
    let before_facts = line_value(&before_status, "facts")
        .parse::<usize>()
        .expect("facts count before generate");

    let generated = assert_success(topo(&[
        "--db",
        &db,
        "--at",
        "4000000000000",
        "generate",
        &workspace_id,
        "7",
        "128",
    ]));
    assert!(generated.contains("generated_facts: 7"), "{generated}");
    assert!(generated.contains("applied_facts: 7"), "{generated}");
    assert!(generated.contains("message_text_bytes: 108"), "{generated}");
    assert!(
        generated.contains("first_timestamp: 4000000000000"),
        "{generated}"
    );
    assert!(
        generated.contains("last_timestamp: 4000000000006"),
        "{generated}"
    );
    wait_for_content_count(&db, &workspace_id, "7");

    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&messages, "messages"), "7");

    let content = assert_success(topo(&["--db", &db, "content-count", &workspace_id]));
    assert_eq!(line_value(&content, "content_messages"), "7");
    assert_eq!(line_value(&content, "message_payload_bytes"), "896");

    let status = assert_success(topo(&["--db", &db, "count"]));
    assert_eq!(
        line_value(&status, "facts")
            .parse::<usize>()
            .expect("facts count after generate"),
        before_facts + 14
    );
    assert_eq!(
        line_value(&status, "applied_facts")
            .parse::<usize>()
            .expect("applied facts count after generate"),
        before_facts + 14
    );
}

#[test]
fn generate_cli_can_profile_runtime_phases_to_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "profiled-generate.db");
    let workspace_id = create_workspace(&db);
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let output = con_cli_with_env(
        &["--db", &db, "generate", &workspace_id, "2", "64"],
        &[("TOPO_PROFILE_GENERATE", "1")],
    );
    assert!(
        output.status.success(),
        "command failed\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    let out = stdout(&output);
    assert!(out.contains("generated_facts: 2"), "{out}");
    let err = stderr(&output);
    assert!(err.contains("generate_profile status=ok"), "{err}");
    assert!(err.contains("command_build_ms="), "{err}");
    assert!(err.contains("commit_ms="), "{err}");
    assert!(
        !err.contains("intent_dispatch_ms="),
        "generate command should not dispatch handlers\n{err}"
    );
}

#[test]
fn explicit_at_sets_generated_fact_timestamps() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "explicit-at-generate.db");
    let workspace_id = create_workspace(&db);
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let generated = assert_success(topo(&[
        "--db",
        &db,
        "--at",
        "4000000005000",
        "generate",
        &workspace_id,
        "3",
        "32",
    ]));
    assert_eq!(line_value(&generated, "first_timestamp"), "4000000005000");
    assert_eq!(line_value(&generated, "last_timestamp"), "4000000005002");
    wait_for_content_count(&db, &workspace_id, "3");

    let generated = assert_success(topo(&[
        "--db",
        &db,
        "--at",
        "4000000005100",
        "generate",
        &workspace_id,
        "1",
        "32",
    ]));
    assert_eq!(line_value(&generated, "first_timestamp"), "4000000005100");
    assert_eq!(line_value(&generated, "last_timestamp"), "4000000005100");
    wait_for_content_count(&db, &workspace_id, "4");
}

#[test]
fn generate_cli_requires_current_storage_before_authoring() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "stale-generate.db");
    let workspace_id = create_workspace(&db);
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    let current_storage_version = stored_storage_version(&db);
    replace_stored_storage_version(&db, current_storage_version - 1);

    let output = topo(&["--db", &db, "generate", &workspace_id, "2", "64"]);
    assert!(
        !output.status.success(),
        "generate should fail before reading stale command state"
    );
    let err = stderr(&output);
    assert!(
        err.contains("protocol update required"),
        "generate should fail with the storage guard: {err}"
    );
}

#[test]
fn assert_eventually_cli_reports_true_when_condition_is_met() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "assert-eventually.db");
    let workspace_id = create_workspace(&db);
    let _daemon = spawn_daemon(&db, free_port());
    create_local_content_key(&db, &workspace_id);

    assert_success(topo(&["--db", &db, "generate", &workspace_id, "2", "64"]));
    let out = assert_success(topo(&[
        "--db",
        &db,
        "assert",
        "eventually",
        "content-count",
        &workspace_id,
        "content_messages",
        ">=",
        "2",
        "--timeout-ms",
        "1000",
        "--poll-ms",
        "10",
    ]));

    assert_eq!(line_value(&out, "ok"), "true");
    assert_eq!(
        line_value(&out, "command"),
        format!("content-count {workspace_id}")
    );
    assert_eq!(line_value(&out, "field"), "content_messages");
    assert_eq!(line_value(&out, "observed"), "2");
}

#[test]
fn assert_eventually_cli_times_out_when_condition_is_not_met() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "assert-eventually-timeout.db");
    let workspace_id = create_workspace(&db);

    let out = topo(&[
        "--db",
        &db,
        "assert",
        "eventually",
        "content-count",
        &workspace_id,
        "content_messages",
        ">=",
        "1",
        "--timeout-ms",
        "10",
        "--poll-ms",
        "1",
    ]);

    assert!(!out.status.success(), "assertion should time out");
    let err = stderr(&out);
    assert!(err.contains("assert eventually timed out"), "{err}");
    assert!(err.contains("last observed 0"), "{err}");
}

fn create_workspace(db: &str) -> String {
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        "Generate",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));
    let workspace_id = line_value(&out, "workspace_id");
    let _daemon = spawn_daemon(db, free_port());
    wait_for_users_contains(db, &workspace_id, "alice");
    wait_for_identity_contains(db, "endpoint_role=device");
    workspace_id
}

fn create_local_content_key(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "key-frontier", workspace_id]));
    wait_for_keys_value(db, workspace_id, "local_key_secrets", "1");
    wait_for_keys_value(db, workspace_id, "removal_frontiers", "1");
    out
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
        "content count did not reach {expected}\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
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

fn replace_stored_storage_version(db: &str, version: u32) {
    let conn = Connection::open(db).expect("open fixture db");
    conn.execute("DELETE FROM protocol_version_rows", [])
        .expect("clear protocol version marker");
    conn.execute(
        "INSERT INTO protocol_version_rows (update_fact_id, protocol_version, applied_at_ms)
         VALUES (?1, ?2, ?3)",
        params![vec![0x55_u8; 32], i64::from(version), 1_i64],
    )
    .expect("write stale protocol version marker");
}

fn stored_storage_version(db: &str) -> u32 {
    let conn = Connection::open(db).expect("open fixture db");
    conn.query_row(
        "SELECT protocol_version
         FROM protocol_version_rows
         ORDER BY applied_at_ms DESC, update_fact_id DESC
         LIMIT 1",
        [],
        |row| row.get::<_, i64>(0).map(|value| value as u32),
    )
    .expect("stored protocol version")
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

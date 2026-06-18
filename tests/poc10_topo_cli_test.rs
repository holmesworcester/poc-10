//! CLI tests that drive the `con` binary in the target shape.
//!
//! Follows the same daemon-and-CLI model as the poc-8 e2e tests: build the
//! `con` binary once, then exercise the target-tree subcommands by spawning
//! the binary through the shared `cli_harness`. Smoke coverage belongs here as
//! black-box checks on the real binary, not as an in-crate demo command.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;

#[test]
fn con_help_is_served_by_the_product_boundary() {
    let stdout = assert_success(con_cli(&["--help"]));

    assert!(
        stdout.contains("Context CLI")
            && stdout.contains("con --db PATH [--at TIMESTAMP_MS] create-workspace")
            && stdout.contains("NAME --username USER --devicename DEVICE")
            && stdout.contains("con --db PATH [--at TIMESTAMP_MS] workspaces")
            && stdout.contains("con --db PATH [--at TIMESTAMP_MS] count")
            && stdout.contains("con --db PATH start --listen IP PORT")
            && stdout.contains("target core runtime facade")
            && !stdout.contains("legacy"),
        "top-level help should describe the target app boundary; got:\n{stdout}"
    );
}

#[test]
fn con_without_a_command_does_not_enter_legacy_cli() {
    let output = con_cli(&[]);

    assert!(
        !output.status.success(),
        "missing command should fail with top-level usage"
    );
    let stderr = cli_harness::stderr(&output);
    assert!(
        stderr.contains("missing command")
            && stderr.contains("con --db PATH [--at TIMESTAMP_MS] create-workspace")
            && stderr.contains("NAME --username USER --devicename DEVICE")
            && !stderr.contains("legacy"),
        "missing command should be rejected at the target app boundary; got:\n{stderr}"
    );
}

#[test]
fn con_demo_is_rejected_at_the_product_boundary() {
    let output = con_cli(&["demo"]);

    assert!(
        !output.status.success(),
        "`con demo` must not remain as a hidden smoke path"
    );
    let stderr = cli_harness::stderr(&output);
    assert!(
        stderr.contains("unknown command `demo`")
            && stderr.contains("con --db PATH [--at TIMESTAMP_MS] create-workspace")
            && stderr.contains("NAME --username USER --devicename DEVICE")
            && !stderr.contains("walkthrough"),
        "`con demo` should be rejected by the central CLI registry; got:\n{stderr}"
    );
}

#[test]
fn con_negentropy_drain_is_not_registered() {
    let output = con_cli(&["negentropy-drain"]);

    assert!(
        !output.status.success(),
        "`negentropy-drain` should not remain as a compatibility command"
    );
    let stderr = cli_harness::stderr(&output);
    assert!(
        stderr.contains("unknown command `negentropy-drain`")
            && stderr.contains("con --db PATH [--at TIMESTAMP_MS] sync-status")
            && !stderr.contains("negentropy-drain [LIMIT]"),
        "`negentropy-drain` should be rejected while `sync-status` remains available; got:\n{stderr}"
    );
}

#[test]
fn con_chop_now_is_not_registered() {
    let output = con_cli(&["chop-now"]);

    assert!(
        !output.status.success(),
        "`chop-now` should not remain as a product CLI command"
    );
    let stderr = cli_harness::stderr(&output);
    assert!(
        stderr.contains("unknown command `chop-now`")
            && stderr.contains(
                "con --db PATH [--at TIMESTAMP_MS] disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]"
            )
            && !stderr.contains("con --db PATH chop-now"),
        "`chop-now` should be rejected while retention-floor commands remain available; got:\n{stderr}"
    );
}

#[test]
fn con_cascade_fixture_commands_are_not_registered() {
    for command in ["test-generate-deps", "test-replay-deps-reverse"] {
        let output = con_cli(&[command]);

        assert!(
            !output.status.success(),
            "`{command}` should not remain as a product CLI command"
        );
        let stderr = cli_harness::stderr(&output);
        assert!(
        stderr.contains(&format!("unknown command `{command}`"))
                && stderr.contains("con --db PATH [--at TIMESTAMP_MS] replay-check")
                && !stderr.contains("cascade"),
            "`{command}` should be rejected while replay-check diagnostics remain available; got:\n{stderr}"
        );
    }
}

#[test]
fn con_create_workspace_accepts_positional_identity_shape() {
    let temp = tempfile::tempdir().expect("temp dir");
    let db = temp_db(&temp, "con.db");
    let _daemon = spawn_daemon(&db, free_port());

    let stdout = assert_success(con_cli(&[
        "--db",
        &db,
        "create-workspace",
        "Runtime Team",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));

    let workspace_id = line_value(&stdout, "workspace_id");
    assert_eq!(workspace_id.len(), 64);
    assert!(stdout.contains("name: Runtime Team"));
    wait_for_workspaces_contains(&db, "1", &workspace_id);

    let workspaces = assert_success(con_cli(&["--db", &db, "workspaces"]));
    assert!(
        workspaces.contains("workspaces: 1") && workspaces.contains(&workspace_id),
        "created workspace should be projected through target rows; got:\n{workspaces}"
    );
}

#[test]
fn con_create_workspace_uses_target_runtime() {
    let temp = tempfile::tempdir().expect("temp dir");
    let db = temp_db(&temp, "con.db");
    let _daemon = spawn_daemon(&db, free_port());

    let stdout = assert_success(con_cli(&[
        "--db",
        &db,
        "create-workspace",
        "Runtime CLI",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));

    let workspace_id = line_value(&stdout, "workspace_id");
    assert_eq!(workspace_id.len(), 64);
    assert!(stdout.contains("name: Runtime CLI"));
    wait_for_workspaces_contains(&db, "1", &workspace_id);

    let workspaces = assert_success(con_cli(&["--db", &db, "workspaces"]));
    assert!(
        workspaces.contains("workspaces: 1")
            && workspaces.contains(&workspace_id)
            && workspaces.contains(" name=Runtime CLI"),
        "created workspace should be visible through the real read command; got:\n{workspaces}"
    );
}

#[test]
fn con_workspace_reads_use_target_rows() {
    let temp = tempfile::tempdir().expect("temp dir");
    let db = temp_db(&temp, "con.db");
    let _daemon = spawn_daemon(&db, free_port());

    assert_success(con_cli(&[
        "--db",
        &db,
        "create-workspace",
        "Alpha",
        "--username",
        "alice-alpha",
        "--devicename",
        "alice-alpha-laptop",
    ]));
    wait_for_workspaces_contains(&db, "1", " name=Alpha");
    assert_success(con_cli(&[
        "--db",
        &db,
        "create-workspace",
        "Beta",
        "--username",
        "alice-beta",
        "--devicename",
        "alice-beta-laptop",
    ]));
    wait_for_workspaces_contains(&db, "2", " name=Beta");

    let workspaces = assert_success(con_cli(&["--db", &db, "workspaces"]));
    assert!(
        workspaces.contains("workspaces: 2")
            && workspaces.contains(" name=Alpha")
            && workspaces.contains(" name=Beta"),
        "workspace list should be decoded from target rows; got:\n{workspaces}"
    );

    let count = assert_success(con_cli(&["--db", &db, "count"]));
    assert_eq!(line_value(&count, "workspace_rows"), "2");
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
    let mut child = spawn_con(&[
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
    if let Some(stderr) = child.stderr.take() {
        thread::spawn(move || for _ in BufReader::new(stderr).lines() {});
    }
    let mut first = String::new();
    BufReader::new(stdout)
        .read_line(&mut first)
        .expect("daemon first line");
    assert!(
        first.starts_with("listening: "),
        "daemon did not report listening: {first}"
    );
    RunningDaemon { child }
}

fn wait_for_workspaces_contains(db: &str, expected_count: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = con_cli(&["--db", db, "workspaces"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "workspaces") == expected_count && out.contains(expected) {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("workspaces did not reach {expected_count} with {expected}: {last}");
}

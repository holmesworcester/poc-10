//! CLI tests that drive the `con` binary in the target shape.
//!
//! Follows the same daemon-and-CLI model as the poc-8 e2e tests: build the
//! `con` binary once, then exercise the target-tree subcommands by spawning
//! the binary through the shared `cli_harness`. Smoke coverage belongs here as
//! black-box checks on the real binary, not as an in-crate demo command.

mod cli_harness;

use cli_harness::{assert_success, con_cli, line_value, temp_db};

#[test]
fn con_help_is_served_by_the_product_boundary() {
    let stdout = assert_success(con_cli(&["--help"]));

    assert!(
        stdout.contains("Context CLI")
            && stdout.contains("con --db PATH create-workspace")
            && stdout.contains("NAME --username USER --devicename DEVICE")
            && stdout.contains("con --db PATH workspaces")
            && stdout.contains("con --db PATH count")
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
            && stderr.contains("con --db PATH create-workspace")
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
            && stderr.contains("con --db PATH create-workspace")
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
            && stderr.contains("con --db PATH sync-status")
            && !stderr.contains("negentropy-drain [LIMIT]"),
        "`negentropy-drain` should be rejected while `sync-status` remains available; got:\n{stderr}"
    );
}

#[test]
fn con_create_workspace_accepts_positional_identity_shape() {
    let temp = tempfile::tempdir().expect("temp dir");
    let db = temp_db(&temp, "con.db");

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

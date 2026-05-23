//! CLI tests that drive the `match` binary in the target shape.
//!
//! Follows the same daemon-and-CLI model as the poc-8 e2e tests: build the
//! `match` binary once, then exercise the target-tree subcommands by spawning
//! the binary through the shared `cli_harness`. Smoke coverage belongs here as
//! black-box checks on the real binary, not as an in-crate demo command.

mod cli_harness;

use cli_harness::{assert_success, line_value, match_cli, temp_db};

#[test]
fn match_help_is_served_by_the_product_boundary() {
    let stdout = assert_success(match_cli(&["--help"]));

    assert!(
        stdout.contains("match --db PATH create-workspace")
            && stdout.contains("NAME --username USER --devicename DEVICE")
            && stdout.contains("match --db PATH workspaces")
            && stdout.contains("match --db PATH count")
            && stdout.contains("match --db PATH start --listen IP PORT")
            && stdout.contains("target core runtime facade")
            && !stdout.contains("legacy"),
        "top-level help should describe the target app boundary; got:\n{stdout}"
    );
}

#[test]
fn match_without_a_command_does_not_enter_legacy_cli() {
    let output = match_cli(&[]);

    assert!(
        !output.status.success(),
        "missing command should fail with top-level usage"
    );
    let stderr = cli_harness::stderr(&output);
    assert!(
        stderr.contains("missing command")
            && stderr.contains("match --db PATH create-workspace")
            && stderr.contains("NAME --username USER --devicename DEVICE")
            && !stderr.contains("legacy"),
        "missing command should be rejected at the target app boundary; got:\n{stderr}"
    );
}

#[test]
fn match_demo_is_rejected_at_the_product_boundary() {
    let output = match_cli(&["demo"]);

    assert!(
        !output.status.success(),
        "`match demo` must not remain as a hidden smoke path"
    );
    let stderr = cli_harness::stderr(&output);
    assert!(
        stderr.contains("unknown command `demo`")
            && stderr.contains("match --db PATH create-workspace")
            && stderr.contains("NAME --username USER --devicename DEVICE")
            && !stderr.contains("walkthrough"),
        "`match demo` should be rejected by the central CLI registry; got:\n{stderr}"
    );
}

#[test]
fn match_negentropy_drain_is_not_registered() {
    let output = match_cli(&["negentropy-drain"]);

    assert!(
        !output.status.success(),
        "`negentropy-drain` should not remain as a compatibility command"
    );
    let stderr = cli_harness::stderr(&output);
    assert!(
        stderr.contains("unknown command `negentropy-drain`")
            && stderr.contains("match --db PATH sync-status")
            && !stderr.contains("negentropy-drain [LIMIT]"),
        "`negentropy-drain` should be rejected while `sync-status` remains available; got:\n{stderr}"
    );
}

#[test]
fn match_create_workspace_accepts_positional_identity_shape() {
    let temp = tempfile::tempdir().expect("temp dir");
    let db = temp_db(&temp, "match.db");

    let stdout = assert_success(match_cli(&[
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

    let workspaces = assert_success(match_cli(&["--db", &db, "workspaces"]));
    assert!(
        workspaces.contains("workspaces: 1") && workspaces.contains(&workspace_id),
        "created workspace should be projected through target rows; got:\n{workspaces}"
    );
}

#[test]
fn match_create_workspace_uses_target_runtime() {
    let temp = tempfile::tempdir().expect("temp dir");
    let db = temp_db(&temp, "match.db");
    let public_key = "0707070707070707070707070707070707070707070707070707070707070707";

    let stdout = assert_success(match_cli(&[
        "--db",
        &db,
        "create-workspace",
        "--public-key",
        public_key,
        "--name",
        "Runtime CLI",
    ]));

    let workspace_id = line_value(&stdout, "workspace_id");
    assert_eq!(workspace_id.len(), 64);
    assert!(stdout.contains("name: Runtime CLI"));

    let workspaces = assert_success(match_cli(&["--db", &db, "workspaces"]));
    assert!(
        workspaces.contains("workspaces: 1")
            && workspaces.contains(&workspace_id)
            && workspaces.contains(&format!("public_key={public_key} name=Runtime CLI")),
        "created workspace should be visible through the real read command; got:\n{workspaces}"
    );
}

#[test]
fn match_workspace_reads_use_target_rows() {
    let temp = tempfile::tempdir().expect("temp dir");
    let db = temp_db(&temp, "match.db");

    assert_success(match_cli(&[
        "--db",
        &db,
        "create-workspace",
        "--public-key",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "--name",
        "Alpha",
    ]));
    assert_success(match_cli(&[
        "--db",
        &db,
        "create-workspace",
        "--public-key",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "--name",
        "Beta",
    ]));

    let workspaces = assert_success(match_cli(&["--db", &db, "workspaces"]));
    assert!(
        workspaces.contains("workspaces: 2")
            && workspaces.contains(
                "public_key=0101010101010101010101010101010101010101010101010101010101010101 name=Alpha"
            )
            && workspaces.contains(
                "public_key=0202020202020202020202020202020202020202020202020202020202020202 name=Beta"
            ),
        "workspace list should be decoded from target rows; got:\n{workspaces}"
    );

    let count = assert_success(match_cli(&["--db", &db, "count"]));
    assert_eq!(line_value(&count, "workspace_rows"), "2");
}

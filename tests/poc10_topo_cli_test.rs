//! CLI tests that drive the `topo` binary in the poc-10 target shape.
//!
//! Follows the same daemon-and-CLI model as the poc-8 e2e tests: build the
//! `topo` binary once, then exercise the target-tree subcommands by
//! spawning the binary through the shared `cli_harness`. As more target
//! subcommands land (`topo poc10-daemon start`, `topo poc10-send`, etc.),
//! their tests should sit here next to this walkthrough so the daemon
//! model stays a real binary contract rather than an in-process fixture.

mod cli_harness;

use cli_harness::{assert_success, topo};

#[test]
fn topo_poc10_demo_runs_the_target_walkthrough() {
    let output = topo(&["poc10-demo"]);
    let stdout = assert_success(output);

    // The walkthrough is structured by named steps. Pin the high-level
    // structure so regressions surface as a missing step rather than as a
    // silent change in semantics.
    for marker in [
        "step 1: admit workspace fact",
        "workspace_rows materialised: 1",
        "step 2: admit signer + sealed message + secret coverage",
        "sealed_message_rows: 1",
        "step 3: open sealed message into message_rows",
        "message_rows (opened): 1",
        "step 4: send_message through CommandContext",
        "recovered plaintext via workspace key: \"via CommandContext\"",
        "No legacy code path was used",
    ] {
        assert!(
            stdout.contains(marker),
            "expected stdout to contain `{marker}`; got:\n{stdout}"
        );
    }
}

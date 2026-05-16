//! CLI tests that drive the `match` binary in the target shape.
//!
//! Follows the same daemon-and-CLI model as the poc-8 e2e tests: build the
//! `match` binary once, then exercise the target-tree subcommands by
//! spawning the binary through the shared `cli_harness`. As more target
//! subcommands land (`match start`, `match send`, etc.),
//! their tests should sit here next to this walkthrough so the daemon
//! model stays a real binary contract rather than an in-process fixture.

mod cli_harness;

use cli_harness::{assert_success, topo};

#[test]
fn match_demo_runs_the_target_walkthrough() {
    let output = topo(&["demo"]);
    let stdout = assert_success(output);

    // The walkthrough is structured by named steps. Pin the high-level
    // structure so regressions surface as a missing step rather than as a
    // silent change in semantics.
    for marker in [
        "step 1: admit workspace fact",
        "workspace_rows materialised: 1",
        "step 2: admit signer + sealed message + secret coverage",
        "sealed_message_rows: 1",
        "step 3: confirm opened message rows are not synthesized",
        "message_rows (opened): 0",
        "no fake plaintext row was written",
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

mod cli_harness;

use std::fs;

use cli_harness::*;

#[test]
fn daemon_diagnostics_reports_live_lock_and_stderr_tail() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    fs::write(
        daemon_lock_path(&db),
        format!("{}\n127.0.0.1:45123\n", std::process::id()),
    )
    .unwrap();
    fs::write(
        daemon_stderr_path(&db),
        "first daemon line\nlast daemon line\n",
    )
    .unwrap();

    let diagnostics = daemon_diagnostics("alice", &db);

    assert!(
        diagnostics.contains("alice daemon diagnostics:"),
        "{diagnostics}"
    );
    assert!(
        diagnostics.contains(&format!("lock_pid: {}", std::process::id())),
        "{diagnostics}"
    );
    assert!(
        diagnostics.contains("lock_addr: 127.0.0.1:45123"),
        "{diagnostics}"
    );
    assert!(diagnostics.contains("process_alive: true"), "{diagnostics}");
    assert!(diagnostics.contains("last daemon line"), "{diagnostics}");
}

#[test]
fn daemon_diagnostics_reports_missing_lock_and_missing_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "missing.db");

    let diagnostics = daemon_diagnostics("missing", &db);

    assert!(
        diagnostics.contains("missing daemon diagnostics:"),
        "{diagnostics}"
    );
    assert!(diagnostics.contains("lock_state: missing"), "{diagnostics}");
    assert!(
        diagnostics.contains("stderr_tail:\n<missing>"),
        "{diagnostics}"
    );
}

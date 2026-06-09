mod cli_harness;

use cli_harness::*;

#[test]
fn generate_cli_uses_real_store_and_reports_applied_facts() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "generate.db");
    let workspace_id = create_workspace(&db);
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));
    let before_status = assert_success(topo(&["--db", &db, "count"]));
    let before_facts = line_value(&before_status, "facts")
        .parse::<usize>()
        .expect("facts count before generate");

    let generated = assert_success(topo(&["--db", &db, "generate", &workspace_id, "7", "128"]));
    assert!(generated.contains("generated_facts: 7"), "{generated}");
    assert!(generated.contains("applied_facts: 7"), "{generated}");
    assert!(generated.contains("message_text_bytes: 108"), "{generated}");
    assert!(generated.contains("first_timestamp: 1"), "{generated}");
    assert!(generated.contains("last_timestamp: 7"), "{generated}");

    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&messages, "messages"), "7");

    let content = assert_success(topo(&["--db", &db, "content-count", &workspace_id]));
    assert_eq!(line_value(&content, "content_messages"), "7");
    assert_eq!(line_value(&content, "message_payload_bytes"), "896");

    let status = assert_success(topo(&["--db", &db, "count"]));
    let generated_wire_facts = 7 * 3;
    assert_eq!(
        line_value(&status, "facts")
            .parse::<usize>()
            .expect("facts count after generate"),
        before_facts + generated_wire_facts
    );
    assert_eq!(
        line_value(&status, "applied_facts")
            .parse::<usize>()
            .expect("applied facts count after generate"),
        before_facts + generated_wire_facts
    );
}

#[test]
fn generate_cli_can_profile_pipeline_phases_to_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "profiled-generate.db");
    let workspace_id = create_workspace(&db);
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

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
    assert!(err.contains("projection_ms="), "{err}");
    assert!(err.contains("projection_load_pending_fact_ms="), "{err}");
    assert!(err.contains("projection_prepare_effects_ms="), "{err}");
    assert!(err.contains("projection_projector_cpu_ms="), "{err}");
    assert!(err.contains("projection_commit_effects_ms="), "{err}");
    assert!(err.contains("projection_replace_context_ms="), "{err}");
    assert!(err.contains("projection_wake_context_matches_ms="), "{err}");
    assert!(err.contains("intent_dispatch_ms="), "{err}");
    assert!(err.contains("share_record_sync_contribution_ms="), "{err}");
    assert!(err.contains("negentropy_update_path_ms="), "{err}");
}

#[test]
fn clock_cli_sets_logical_timestamp_lower_bound_for_generated_facts() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "clocked-generate.db");
    let workspace_id = create_workspace(&db);
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    let set = assert_success(topo(&["--db", &db, "clock", "set", "5000"]));
    assert_eq!(line_value(&set, "logical_time"), "5000");
    assert_eq!(line_value(&set, "next_timestamp"), "5000");

    let generated = assert_success(topo(&["--db", &db, "generate", &workspace_id, "3", "32"]));
    assert_eq!(line_value(&generated, "first_timestamp"), "5000");
    assert_eq!(line_value(&generated, "last_timestamp"), "5002");

    let advanced = assert_success(topo(&["--db", &db, "clock", "advance", "100"]));
    assert_eq!(line_value(&advanced, "logical_time"), "5100");
    assert_eq!(line_value(&advanced, "max_observed_timestamp"), "5002");
    assert_eq!(line_value(&advanced, "next_timestamp"), "5100");

    let generated = assert_success(topo(&["--db", &db, "generate", &workspace_id, "1", "32"]));
    assert_eq!(line_value(&generated, "first_timestamp"), "5100");
    assert_eq!(line_value(&generated, "last_timestamp"), "5100");

    let cleared = assert_success(topo(&["--db", &db, "clock", "clear"]));
    assert_eq!(line_value(&cleared, "logical_time"), "unset");
    assert_eq!(line_value(&cleared, "next_timestamp"), "5101");
}

#[test]
fn assert_eventually_cli_reports_true_when_condition_is_met() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "assert-eventually.db");
    let workspace_id = create_workspace(&db);
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

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
    line_value(&out, "workspace_id")
}

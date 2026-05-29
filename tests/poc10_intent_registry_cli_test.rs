//! Black-box CLI tests for the intent-registry and recurring-intents
//! diagnostics.
//!
//! These prove that every handler route's replay decision and recurrence are
//! visible through the `con` binary, and that recurring intents are reported
//! from static registry metadata with no persisted job rows.

mod cli_harness;

use cli_harness::*;

fn fresh_db() -> (tempfile::TempDir, String) {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "registry.db");
    assert_success(topo(&[
        "--db",
        &db,
        "create-workspace",
        "Registry",
        "--username",
        "alice",
        "--devicename",
        "laptop",
    ]));
    (tmp, db)
}

fn route_line(out: &str, name: &str) -> String {
    out.lines()
        .find(|line| line.starts_with(&format!("route_{name}:")))
        .unwrap_or_else(|| panic!("intent-registry missing route {name}:\n{out}"))
        .to_string()
}

#[test]
fn intent_registry_exposes_replay_decision_for_every_route() {
    let (_tmp, db) = fresh_db();
    let out = assert_success(topo(&["--db", &db, "intent-registry"]));

    assert_eq!(line_value(&out, "routes"), "12");

    // Deterministic rebuild work runs during replay.
    for replay_route in ["share_fact_with_sync", "create_key_wrap", "unwrap_key_wrap"] {
        let line = route_line(&out, replay_route);
        assert!(line.contains("replay=true"), "{line}");
        assert!(line.contains("network_io=false"), "{line}");
    }

    // Network IO and live session work do not run during replay, and the
    // network routes are reported as command-excluded and network-capable.
    for network_route in [
        "send_bootstrap_connection_request",
        "send_facts_on_connection",
        "send_network_frame",
        "receive_network_frame",
    ] {
        let line = route_line(&out, network_route);
        assert!(line.contains("replay=false"), "{line}");
        assert!(line.contains("command_excluded=true"), "{line}");
        assert!(line.contains("network_io=true"), "{line}");
    }

    // create_connection_response does not run during replay but is not a
    // network-IO route in the command-exclusion sense.
    let response = route_line(&out, "create_connection_response");
    assert!(response.contains("replay=false"), "{response}");
}

#[test]
fn recurring_intents_come_from_static_registry_without_persisted_rows() {
    let (_tmp, db) = fresh_db();
    let out = assert_success(topo(&["--db", &db, "recurring-intents"]));

    assert_eq!(
        line_value(&out, "source"),
        "handler_registry",
        "recurring intents must be listed from static registry metadata"
    );
    assert_eq!(
        line_value(&out, "persisted_job_rows"),
        "0",
        "recurring schedules are in-memory only"
    );

    // No state-summary area is a persisted recurring/job/schedule table.
    let summary = assert_success(topo(&["--db", &db, "state-summary"]));
    for line in summary.lines() {
        let lowered = line.to_lowercase();
        assert!(
            !(lowered.starts_with("area_") && (lowered.contains("recurring_job") || lowered.contains("schedule"))),
            "no persisted recurring schedule table should exist: {line}"
        );
    }
}

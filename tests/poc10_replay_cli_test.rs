//! Black-box CLI tests for the replay entry point and deterministic state
//! summary.
//!
//! Setup goes through the real `con` binary: a workspace and content messages
//! are authored, then `replay` rebuilds derived state from retained facts. The
//! tests prove the replay/intent-shape guarantees: replay is idempotent, drops
//! queued intents, recreates sync- and key-wrap-derived state, never crosses the
//! network barrier, and reaches the same state digest regardless of fact
//! projection order.

mod cli_harness;

use cli_harness::*;

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
    line_value(&out, "workspace_id")
}

fn seed_workspace_with_content(db: &str) -> String {
    let workspace_id = create_workspace(db, "Replay", "alice", "laptop");
    assert_success(topo(&["--db", db, "key-frontier", &workspace_id]));
    assert_success(topo(&["--db", db, "send", &workspace_id, "first message"]));
    assert_success(topo(&["--db", db, "send", &workspace_id, "second message"]));
    workspace_id
}

fn state_hash(db: &str) -> String {
    line_value(&assert_success(topo(&["--db", db, "state-summary"])), "state_hash")
}

#[test]
fn replay_is_idempotent_and_rebuilds_derived_state() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = seed_workspace_with_content(&db);

    let before = state_hash(&db);

    let replay = assert_success(topo(&["--db", &db, "replay"]));
    assert_eq!(
        line_value(&replay, "order"),
        "canonical",
        "default replay uses canonical fact order"
    );
    assert_eq!(
        line_value(&replay, "network_rows"),
        "0",
        "replay must not produce network rows before the barrier"
    );
    assert_eq!(
        line_value(&replay, "blocked_live_only_work"),
        "0",
        "this offline scenario should not leave live-only work queued"
    );
    assert!(
        line_value(&replay, "retained_facts").parse::<u64>().unwrap() > 0,
        "replay should reproject retained facts"
    );
    assert!(
        line_value(&replay, "row_mutations").parse::<u64>().unwrap() > 0,
        "replay should rebuild materialized read-model rows"
    );
    assert!(
        line_value(&replay, "replay_allowed_intents")
            .parse::<u64>()
            .unwrap()
            > 0,
        "replay should recreate sync and key-wrap work through replay-allowed intents"
    );

    let after = state_hash(&db);
    assert_eq!(before, after, "replay must rebuild byte-identical state");

    // The rebuilt read model still answers content queries.
    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(messages.contains("first message"), "{messages}");
    assert!(messages.contains("second message"), "{messages}");
}

#[test]
fn second_replay_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    assert_success(topo(&["--db", &db, "replay"]));
    let once = state_hash(&db);
    assert_success(topo(&["--db", &db, "replay"]));
    let twice = state_hash(&db);
    assert_eq!(once, twice, "replay is idempotent");
}

#[test]
fn replay_reverse_rebuilds_same_state_as_canonical() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let before = state_hash(&db);
    let replay = assert_success(topo(&["--db", &db, "replay", "--reverse"]));
    assert_eq!(line_value(&replay, "order"), "reverse");
    assert_eq!(line_value(&replay, "network_rows"), "0");
    let after = state_hash(&db);
    assert_eq!(
        before, after,
        "reverse projection order must reach the same state"
    );
}

#[test]
fn replay_scramble_rebuilds_same_state_as_canonical() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let before = state_hash(&db);
    let replay = assert_success(topo(&["--db", &db, "replay", "--scramble", "--seed", "7"]));
    assert_eq!(line_value(&replay, "order"), "scramble:7");
    assert_eq!(line_value(&replay, "network_rows"), "0");
    let after = state_hash(&db);
    assert_eq!(
        before, after,
        "scrambled projection order must reach the same state"
    );
}

#[test]
fn replay_check_reports_identical_digest_across_orders() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let out = assert_success(topo(&["--db", &db, "replay-check"]));
    assert_eq!(line_value(&out, "ok"), "true", "{out}");
    assert_eq!(line_value(&out, "mismatched_passes"), "0", "{out}");
    assert_eq!(
        line_value(&out, "passes"),
        "6",
        "canonical, idempotent, reverse, and three scrambled passes"
    );

    // replay-check works on scratch copies and must not mutate the live db.
    let live_before = state_hash(&db);
    assert_success(topo(&["--db", &db, "replay-check"]));
    assert_eq!(state_hash(&db), live_before, "replay-check must not mutate the live database");
}

fn area_line(summary: &str, area: &str) -> String {
    summary
        .lines()
        .find(|line| line.starts_with(&format!("area_{area}:")))
        .unwrap_or_else(|| panic!("state-summary missing area {area}:\n{summary}"))
        .to_string()
}

#[test]
fn replay_recreates_key_material_idempotently() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Keys", "alice", "laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));
    assert_success(topo(&["--db", &db, "key-recipient", &workspace_id]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "secret message"]));
    assert_success(topo(&["--db", &db, "key-derive", "64"]));

    let summary_before = assert_success(topo(&["--db", &db, "state-summary"]));
    let key_wrap_before = area_line(&summary_before, "key_wrap_rows");
    // The recipient scenario materializes at least one key wrap.
    let key_wrap_count: u64 = key_wrap_before
        .split_whitespace()
        .nth(1)
        .and_then(|count| count.parse().ok())
        .unwrap();
    assert!(key_wrap_count > 0, "{key_wrap_before}");
    let before = state_hash(&db);

    let replay = assert_success(topo(&["--db", &db, "replay"]));
    // create_key_wrap / unwrap_key_wrap run during replay as deterministic fact
    // creation. They must not duplicate any wrap or local-secret fact, so replay
    // emits no new facts and purges none.
    assert_eq!(
        line_value(&replay, "emitted_facts"),
        "0",
        "replay key-material handlers must not create duplicate facts"
    );
    assert_eq!(line_value(&replay, "purged_facts"), "0");
    assert_eq!(line_value(&replay, "network_rows"), "0");
    assert!(
        line_value(&replay, "replay_allowed_intents")
            .parse::<u64>()
            .unwrap()
            > 0,
        "replay should redispatch key-material work"
    );

    let after = state_hash(&db);
    assert_eq!(before, after, "key material must rebuild identically");
    let summary_after = assert_success(topo(&["--db", &db, "state-summary"]));
    assert_eq!(
        area_line(&summary_after, "key_wrap_rows"),
        key_wrap_before,
        "key wrap rows must be byte-identical after replay"
    );
}

#[test]
fn state_summary_is_stable_and_exposes_per_area_digests() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    seed_workspace_with_content(&db);

    let first = assert_success(topo(&["--db", &db, "state-summary"]));
    let second = assert_success(topo(&["--db", &db, "state-summary"]));
    assert_eq!(first, second, "state summary is a stable read");
    assert!(
        first.lines().any(|line| line.starts_with("area_facts:")),
        "state summary exposes the retained facts area: {first}"
    );
    assert!(
        first.lines().any(|line| line.starts_with("area_content_messages:")),
        "state summary exposes the materialized message rows area: {first}"
    );
    // Volatile scheduler/socket state is excluded from the digest areas.
    assert!(
        !first.lines().any(|line| line.starts_with("area_network_out:")
            || line.starts_with("area_intents:")
            || line.starts_with("area_pending_projection:")),
        "state summary must exclude volatile scheduler and socket state: {first}"
    );
}

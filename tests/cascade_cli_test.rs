mod cli_harness;

use std::time::Instant;

use cli_harness::*;

#[test]
fn cascade_cli_replays_fact_with_deps_out_of_order_and_unblocks_10k() {
    run_cascade_replay_perf(10_000, false);
}

#[test]
fn cascade_cli_replays_fact_with_deps_out_of_order_and_unblocks_100k() {
    run_cascade_replay_perf(100_000, true);
}

fn run_cascade_replay_perf(count: usize, large: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(
        &tmp,
        if large {
            "cascade-100k.db"
        } else {
            "cascade.db"
        },
    );
    let count_arg = count.to_string();

    let staged = assert_success(topo(&["--db", &db, "test-generate-deps", &count_arg, "10"]));
    assert_eq!(line_value(&staged, "staged_facts"), count_arg);
    assert_eq!(line_value(&staged, "deps_per_fact"), "10");
    assert_eq!(
        line_value(&staged, "dep_edges"),
        expected_dep_edges(count, 10).to_string()
    );
    let status = assert_success(topo(&["--db", &db, "count"]));
    assert_eq!(
        line_value(&status, "facts"),
        "0",
        "staged fixtures must be local-only"
    );

    let started = Instant::now();
    let replayed = assert_success(topo(&["--db", &db, "test-replay-deps-reverse"]));
    let elapsed = started.elapsed();

    assert_eq!(line_value(&replayed, "replayed_facts"), count_arg);
    assert_eq!(line_value(&replayed, "applied_facts"), count_arg);

    let status = assert_success(topo(&["--db", &db, "count"]));
    assert_eq!(line_value(&status, "facts"), count_arg);
    assert_eq!(line_value(&status, "applied_facts"), count_arg);

    let seconds = elapsed.as_secs_f64().max(0.001);
    let rate = count as f64 / seconds;
    eprintln!("black_box_cascade_{count} facts_per_s={rate:.0}");
    assert!(rate.is_finite() && rate > 1_000.0);
}

fn expected_dep_edges(count: usize, deps_per_fact: usize) -> usize {
    (0..count)
        .map(|index| index.min(deps_per_fact))
        .sum::<usize>()
}

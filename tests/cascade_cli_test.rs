mod cli_harness;

use cli_harness::*;

#[test]
fn cascade_cli_blocks_then_unblocks_10k() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "cascade.db");
    let out = assert_success(topo(&db, &["cascade", "10000", "--batch", "4096"]));

    assert_eq!(line_value(&out, "cascade_events"), "10000");
    assert_eq!(line_value(&out, "deps_per_event"), "10");
    assert_eq!(line_value(&out, "blocked_after_reverse"), "9990");
    assert_eq!(line_value(&out, "applied_events"), "10000");
    assert_eq!(line_value(&out, "ready_events_remaining"), "0");
    assert_eq!(line_value(&out, "blocked_events_remaining"), "0");
    assert_eq!(line_value(&out, "blocked_edges_remaining"), "0");

    let rate = line_value(&out, "cascade_events_per_s")
        .parse::<f64>()
        .expect("parse cascade rate");
    eprintln!("black_box_cascade_10k events_per_s={rate:.0}");
    assert!(rate.is_finite() && rate > 0.0);

    let count_out = assert_success(topo(&db, &["count"]));
    assert_eq!(line_value(&count_out, "events"), "10000");
    assert_eq!(line_value(&count_out, "applied_events"), "10000");
    assert_eq!(line_value(&count_out, "blocked_events"), "0");
    assert_eq!(line_value(&count_out, "blocked_edges"), "0");
}

#[test]
#[ignore]
fn cascade_cli_blocks_then_unblocks_50k() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "cascade-50k.db");
    let out = assert_success(topo(&db, &["cascade", "50000", "--batch", "4096"]));

    assert_eq!(line_value(&out, "cascade_events"), "50000");
    assert_eq!(line_value(&out, "blocked_after_reverse"), "49990");
    assert_eq!(line_value(&out, "applied_events"), "50000");
    assert_eq!(line_value(&out, "blocked_events_remaining"), "0");
    assert_eq!(line_value(&out, "blocked_edges_remaining"), "0");
    eprintln!(
        "black_box_cascade_50k events_per_s={}",
        line_value(&out, "cascade_events_per_s")
    );
}

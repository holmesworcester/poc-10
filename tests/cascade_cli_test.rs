use std::time::Instant;

use topo::event_modules::test_events;
use topo::store::{EventStatusCounts, Store};
use topo::{control_loop, pipeline};

#[derive(Debug, Clone, PartialEq)]
struct CascadeReport {
    events: usize,
    deps_per_event: usize,
    dep_edges: usize,
    setup_ms: u128,
    blocking_ms: u128,
    cascade_ms: u128,
    total_ms: u128,
    blocked_after_reverse: usize,
    applied_events: usize,
    unblocked_events: usize,
    final_counts: EventStatusCounts,
}

fn run_cascade(
    store: &Store,
    events: usize,
    deps_per_event: usize,
    batch_size: usize,
) -> Result<CascadeReport, String> {
    if events == 0 {
        return Err("cascade requires at least one event".to_string());
    }

    let total_start = Instant::now();
    let setup_start = Instant::now();
    let start_timestamp = store
        .max_timestamp()
        .map_err(|err| format!("load max timestamp: {err}"))?
        .saturating_add(1);
    let records = test_events::dependent_event::commands::build_records(
        events,
        deps_per_event,
        start_timestamp,
    )?;
    let dep_edges = records.iter().map(|record| record.dependencies.len()).sum();
    let setup_ms = setup_start.elapsed().as_millis();

    let root_count = events.min(deps_per_event);
    let blocking_start = Instant::now();
    let reverse_records = records[root_count..].iter().rev().cloned().collect();
    pipeline::admit_records(store, reverse_records)
        .map_err(|err| format!("insert reverse dependent events: {err}"))?;
    let blocked_after_reverse = store
        .status_counts()
        .map_err(|err| format!("count blocked events: {err}"))?
        .blocked;
    let blocking_ms = blocking_start.elapsed().as_millis();

    let cascade_start = Instant::now();
    pipeline::admit_records(store, records[..root_count].to_vec())
        .map_err(|err| format!("insert root events: {err}"))?;
    let drain = control_loop::drain_until_idle(store, batch_size)?;
    let cascade_ms = cascade_start.elapsed().as_millis();
    let final_counts = store
        .status_counts()
        .map_err(|err| format!("count final event status: {err}"))?;

    Ok(CascadeReport {
        events,
        deps_per_event,
        dep_edges,
        setup_ms,
        blocking_ms,
        cascade_ms,
        total_ms: total_start.elapsed().as_millis(),
        blocked_after_reverse,
        applied_events: drain.applied_events,
        unblocked_events: drain.unblocked_events,
        final_counts,
    })
}

#[test]
fn cascade_bench_blocks_then_unblocks_10k() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().join("cascade.db")).unwrap();
    let report = run_cascade(
        &store,
        10_000,
        test_events::dependent_event::codec::MAX_DEPS,
        control_loop::DEFAULT_READY_BATCH,
    )
    .unwrap();

    assert_eq!(report.events, 10_000);
    assert_eq!(report.deps_per_event, 10);
    assert_eq!(report.blocked_after_reverse, 9_990);
    assert_eq!(report.applied_events, 10_000);
    assert_eq!(report.final_counts.ready, 0);
    assert_eq!(report.final_counts.blocked, 0);
    assert_eq!(report.final_counts.blocked_edges, 0);

    let seconds = (report.cascade_ms as f64 / 1000.0).max(0.001);
    let rate = report.applied_events as f64 / seconds;
    eprintln!("black_box_cascade_10k events_per_s={rate:.0}");
    assert!(rate.is_finite() && rate > 0.0);

    let counts = store.status_counts().unwrap();
    assert_eq!(store.event_count().unwrap(), 10_000);
    assert_eq!(counts.applied, 10_000);
    assert_eq!(counts.blocked, 0);
    assert_eq!(counts.blocked_edges, 0);
}

#[test]
#[ignore]
fn cascade_bench_blocks_then_unblocks_50k() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().join("cascade-50k.db")).unwrap();
    let report = run_cascade(
        &store,
        50_000,
        test_events::dependent_event::codec::MAX_DEPS,
        control_loop::DEFAULT_READY_BATCH,
    );

    let report = report.unwrap();
    assert_eq!(report.events, 50_000);
    assert_eq!(report.blocked_after_reverse, 49_990);
    assert_eq!(report.applied_events, 50_000);
    assert_eq!(report.final_counts.blocked, 0);
    assert_eq!(report.final_counts.blocked_edges, 0);

    let seconds = (report.cascade_ms as f64 / 1000.0).max(0.001);
    let rate = report.applied_events as f64 / seconds;
    eprintln!("black_box_cascade_50k events_per_s={rate:.0}");
}

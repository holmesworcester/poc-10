use std::time::Instant;

use crate::control_loop;
use crate::event_modules::bench_dep;
use crate::store::{EventStatusCounts, Store};

#[derive(Debug, Clone, PartialEq)]
pub struct CascadeReport {
    pub events: usize,
    pub deps_per_event: usize,
    pub dep_edges: usize,
    pub setup_ms: u128,
    pub blocking_ms: u128,
    pub cascade_ms: u128,
    pub total_ms: u128,
    pub blocked_after_reverse: usize,
    pub applied_events: usize,
    pub unblocked_events: usize,
    pub final_counts: EventStatusCounts,
}

pub fn run(
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
    let records = bench_dep::commands::build_records(events, deps_per_event, start_timestamp)?;
    let dep_edges = records.iter().map(|record| record.dependencies.len()).sum();
    let setup_ms = setup_start.elapsed().as_millis();

    let root_count = events.min(deps_per_event);
    let blocking_start = Instant::now();
    let reverse_records = records[root_count..].iter().rev().cloned().collect();
    crate::pipeline::admit_records(store, reverse_records)
        .map_err(|err| format!("insert reverse dependent events: {err}"))?;
    let blocked_after_reverse = store
        .status_counts()
        .map_err(|err| format!("count blocked events: {err}"))?
        .blocked;
    let blocking_ms = blocking_start.elapsed().as_millis();

    let cascade_start = Instant::now();
    crate::pipeline::admit_records(store, records[..root_count].to_vec())
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

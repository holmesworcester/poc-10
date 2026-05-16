//! Commands for building dependency-cascade fixtures as real events.
//!
//! The staging command creates local wrapper events that contain shared event
//! bytes. A CLI test can then replay those shared events in reverse order and
//! prove the common worker's block/unblock path without direct table writes.

use crate::legacy::protocol::event_modules::sync::compare::types::TimestampRange;
use crate::legacy::protocol::event_modules::types::{EventId, EventIndexEntry, EventRecord};
use crate::legacy::protocol::event_modules::worker::CommandOutput;

use super::layout;
use super::types::{EventWithDeps, StagedEventWithDeps, MAX_DEPS, PAYLOAD_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageReport {
    pub staged_events: usize,
    pub deps_per_event: usize,
    pub dep_edges: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecentRootReport {
    pub generated_events: usize,
    pub dep_edges: usize,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecentRootsReport {
    pub generated_events: usize,
    pub dep_edges: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

pub trait EventWithDepsRead {
    fn max_timestamp(&self) -> Result<u64, String>;
    fn event_index_entries(&self) -> Result<Vec<EventIndexEntry>, String>;
}

pub fn build_records(
    events: usize,
    deps_per_event: usize,
    start_timestamp: u64,
) -> Result<Vec<EventRecord>, String> {
    // Each event depends on up to `deps_per_event` immediately preceding events,
    // producing a wide enough cascade to stress unblocking while keeping the
    // graph easy to audit by index.
    if events == 0 {
        return Err("event_with_deps requires at least one event".to_string());
    }
    if deps_per_event == 0 || deps_per_event > MAX_DEPS {
        return Err(format!(
            "event_with_deps deps_per_event must be 1..={MAX_DEPS}"
        ));
    }
    let mut records = Vec::with_capacity(events);
    let mut event_ids = Vec::<EventId>::with_capacity(events);

    for idx in 0..events {
        let dep_count = idx.min(deps_per_event);
        let dependencies = event_ids[idx - dep_count..idx].to_vec();
        let event = EventWithDeps {
            timestamp: start_timestamp + idx as u64,
            dependencies,
            payload: payload(idx),
        };
        let bytes = layout::encode(&event);
        event_ids.push(crate::legacy::protocol::event_modules::types::event_id(
            &bytes,
        ));
        records.push(layout::record_from_bytes(bytes)?);
    }

    Ok(records)
}

pub fn stage_next(
    context: &impl EventWithDepsRead,
    events: usize,
    deps_per_event: usize,
) -> Result<CommandOutput<StageReport>, String> {
    let start_timestamp = context.max_timestamp()?.saturating_add(1);
    stage(events, deps_per_event, start_timestamp)
}

pub fn recent_root_from_old_events(
    context: &impl EventWithDepsRead,
    old_events: usize,
    deps_per_event: usize,
) -> Result<CommandOutput<RecentRootReport>, String> {
    if old_events == 0 {
        return Err("recent event_with_deps root needs at least one old event".to_string());
    }
    if deps_per_event == 0 || deps_per_event > MAX_DEPS {
        return Err(format!(
            "recent event_with_deps deps_per_event must be 1..={MAX_DEPS}"
        ));
    }

    let entries = context.event_index_entries()?;
    if entries.len() < old_events {
        return Err(format!(
            "recent event_with_deps requested {old_events} old events, but only {} are applied",
            entries.len()
        ));
    }

    let old_entries = &entries[..old_events];
    let mut dependencies = old_entries
        .iter()
        .rev()
        .take(deps_per_event)
        .map(|entry| entry.event_id)
        .collect::<Vec<_>>();
    dependencies.reverse();
    let timestamp = TimestampRange::next_day_after(context.max_timestamp()?);
    recent_root(timestamp, dependencies)
}

pub fn recent_roots_with_shared_dep_closure_from_old_events(
    context: &impl EventWithDepsRead,
    old_events: usize,
    recent_events: usize,
) -> Result<CommandOutput<RecentRootsReport>, String> {
    if old_events == 0 {
        return Err("recent event_with_deps roots need at least one old event".to_string());
    }
    if recent_events == 0 {
        return Err("recent event_with_deps roots need at least one recent event".to_string());
    }
    let entries = context.event_index_entries()?;
    if entries.len() < old_events {
        return Err(format!(
            "recent event_with_deps roots requested {old_events} old events, but only {} are applied",
            entries.len()
        ));
    }
    let dependency = entries[old_events - 1].event_id;
    let start_timestamp = TimestampRange::next_day_after(context.max_timestamp()?);
    recent_roots_with_shared_dependency(start_timestamp, recent_events, dependency)
}

pub fn recent_root(
    timestamp: u64,
    dependencies: Vec<EventId>,
) -> Result<CommandOutput<RecentRootReport>, String> {
    if dependencies.is_empty() || dependencies.len() > MAX_DEPS {
        return Err(format!(
            "event_with_deps recent root dependency count must be 1..={MAX_DEPS}"
        ));
    }
    let dep_edges = dependencies.len();
    let event = EventWithDeps {
        timestamp,
        dependencies,
        payload: payload(timestamp as usize),
    };
    let record = layout::record_from_bytes(layout::encode(&event))?;
    Ok(CommandOutput::with_events(
        RecentRootReport {
            generated_events: 1,
            dep_edges,
            timestamp,
        },
        vec![record],
    ))
}

pub fn recent_roots_with_shared_dependency(
    start_timestamp: u64,
    events: usize,
    dependency: EventId,
) -> Result<CommandOutput<RecentRootsReport>, String> {
    if events == 0 {
        return Err("event_with_deps recent roots require at least one event".to_string());
    }
    let mut records = Vec::with_capacity(events);
    for idx in 0..events {
        let timestamp = start_timestamp + idx as u64;
        let event = EventWithDeps {
            timestamp,
            dependencies: vec![dependency],
            payload: payload(start_timestamp as usize + idx),
        };
        records.push(layout::record_from_bytes(layout::encode(&event))?);
    }
    Ok(CommandOutput::with_events(
        RecentRootsReport {
            generated_events: events,
            dep_edges: events,
            first_timestamp: start_timestamp,
            last_timestamp: start_timestamp + events as u64 - 1,
        },
        records,
    ))
}

pub fn stage(
    events: usize,
    deps_per_event: usize,
    start_timestamp: u64,
) -> Result<CommandOutput<StageReport>, String> {
    let records = build_records(events, deps_per_event, start_timestamp)?;
    let dep_edges = records.iter().map(|record| record.dependencies.len()).sum();
    let staged = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let bytes = layout::encode_staged(&StagedEventWithDeps {
                index: index as u64,
                inner_bytes: record.canonical_bytes,
            });
            layout::staged_record_from_bytes(bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CommandOutput::with_events(
        StageReport {
            staged_events: events,
            deps_per_event,
            dep_edges,
            first_timestamp: start_timestamp,
            last_timestamp: start_timestamp + events as u64 - 1,
        },
        staged,
    ))
}

fn payload(idx: usize) -> [u8; PAYLOAD_BYTES] {
    let hash = blake3::hash(&idx.to_be_bytes());
    let mut payload = [0; PAYLOAD_BYTES];
    payload.copy_from_slice(&hash.as_bytes()[..PAYLOAD_BYTES]);
    payload
}

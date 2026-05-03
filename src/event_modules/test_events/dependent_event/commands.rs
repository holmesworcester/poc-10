use crate::store::{CommandOutput, EventId, EventRecord};

use super::codec;
use super::types::{DependentEvent, StagedDependentEvent, MAX_DEPS, PAYLOAD_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageReport {
    pub staged_events: usize,
    pub deps_per_event: usize,
    pub dep_edges: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

pub fn build_records(
    events: usize,
    deps_per_event: usize,
    start_timestamp: u64,
) -> Result<Vec<EventRecord>, String> {
    if events == 0 {
        return Err("cascade requires at least one event".to_string());
    }
    if deps_per_event == 0 || deps_per_event > MAX_DEPS {
        return Err(format!("cascade deps_per_event must be 1..={MAX_DEPS}"));
    }
    let mut records = Vec::with_capacity(events);
    let mut event_ids = Vec::<EventId>::with_capacity(events);

    for idx in 0..events {
        let dep_count = idx.min(deps_per_event);
        let dependencies = event_ids[idx - dep_count..idx].to_vec();
        let event = DependentEvent {
            timestamp: start_timestamp + idx as u64,
            dependencies,
            payload: payload(idx),
        };
        let bytes = codec::encode(&event);
        event_ids.push(crate::store::event_id(&bytes));
        records.push(codec::record_from_bytes(bytes)?);
    }

    Ok(records)
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
            let bytes = codec::encode_staged(&StagedDependentEvent {
                index: index as u64,
                dependent_bytes: record.canonical_bytes,
            });
            codec::staged_record_from_bytes(bytes)
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

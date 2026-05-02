use crate::store::{EventId, EventRecord};

use super::codec;
use super::types::{DependentEvent, MAX_DEPS, PAYLOAD_BYTES};

pub fn build_records(
    events: usize,
    deps_per_event: usize,
    start_timestamp: u64,
) -> Result<Vec<EventRecord>, String> {
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

fn payload(idx: usize) -> [u8; PAYLOAD_BYTES] {
    let hash = blake3::hash(&idx.to_be_bytes());
    let mut payload = [0; PAYLOAD_BYTES];
    payload.copy_from_slice(&hash.as_bytes()[..PAYLOAD_BYTES]);
    payload
}

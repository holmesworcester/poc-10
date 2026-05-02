use crate::store::{EventId, EventRecord};
use crate::wire::{Reader, Writer};

pub const TYPE_BENCH_DEP: u8 = 2;
pub const MAX_DEPS: usize = 10;
pub const PAYLOAD_BYTES: usize = 16;
pub const ENCODED_BYTES: usize = 1 + 8 + 1 + (MAX_DEPS * 32) + PAYLOAD_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentEvent {
    pub timestamp: u64,
    pub dependencies: Vec<EventId>,
    pub payload: [u8; PAYLOAD_BYTES],
}

pub fn encode(event: &DependentEvent) -> Vec<u8> {
    assert!(
        event.dependencies.len() <= MAX_DEPS,
        "bench_dep dependencies exceed fixed field count"
    );
    let mut out = Writer::with_capacity(ENCODED_BYTES);
    out.u8(TYPE_BENCH_DEP);
    out.u64(event.timestamp);
    out.u8(event.dependencies.len() as u8);
    for idx in 0..MAX_DEPS {
        if let Some(dep) = event.dependencies.get(idx) {
            out.id(dep);
        } else {
            out.id(&[0; 32]);
        }
    }
    out.raw(&event.payload);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<DependentEvent, String> {
    if bytes.len() != ENCODED_BYTES {
        return Err("bench_dep event length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes, "bench_dep event");
    let tag = reader.u8()?;
    if tag != TYPE_BENCH_DEP {
        return Err("unknown event type".to_string());
    }
    let timestamp = reader.u64()?;
    let dep_count = reader.u8()? as usize;
    if dep_count > MAX_DEPS {
        return Err("bench_dep dependency count exceeds fixed fields".to_string());
    }

    let mut dependencies = Vec::with_capacity(dep_count);
    for idx in 0..MAX_DEPS {
        let dep = reader.id()?;
        if idx < dep_count {
            dependencies.push(dep);
        } else if dep != [0; 32] {
            return Err("bench_dep unused dependency field is nonzero".to_string());
        }
    }

    let payload = reader.bytes(PAYLOAD_BYTES)?;
    reader.finish()?;
    let mut fixed_payload = [0; PAYLOAD_BYTES];
    fixed_payload.copy_from_slice(&payload);

    Ok(DependentEvent {
        timestamp,
        dependencies,
        payload: fixed_payload,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let decoded = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: decoded.timestamp,
        payload_len: PAYLOAD_BYTES,
        canonical_bytes: bytes,
        dependencies: decoded.dependencies,
    })
}

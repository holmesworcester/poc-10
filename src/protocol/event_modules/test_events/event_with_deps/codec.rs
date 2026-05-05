//! Fixed-width codec for dependency-cascade test events.
//!
//! The event body is deliberately rigid: a timestamp, a bounded dependency
//! array, and a fixed payload. This makes out-of-order replay tests deterministic
//! and makes malformed dependency padding visible. The staged wrapper is a
//! local-only event that stores canonical shared event bytes for later replay.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{EventWithDeps, StagedEventWithDeps, MAX_DEPS, PAYLOAD_BYTES};

pub const TYPE_EVENT_WITH_DEPS: u8 = 2;
pub const TYPE_STAGED_EVENT_WITH_DEPS: u8 = 3;
pub const ENCODED_BYTES: usize = 1 + 8 + 1 + (MAX_DEPS * 32) + PAYLOAD_BYTES;
pub const STAGED_ENCODED_BYTES: usize = 1 + 8 + ENCODED_BYTES;

pub fn encode(event: &EventWithDeps) -> Vec<u8> {
    assert!(
        event.dependencies.len() <= MAX_DEPS,
        "event_with_deps dependencies exceed fixed field count"
    );
    let mut out = Writer::with_capacity(ENCODED_BYTES);
    out.u8(TYPE_EVENT_WITH_DEPS);
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

pub fn decode(bytes: &[u8]) -> Result<EventWithDeps, String> {
    // Unused dependency slots must be zero. This prevents two encodings of the
    // same semantic dependency set from producing different event ids.
    if bytes.len() != ENCODED_BYTES {
        return Err("event_with_deps length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes, "event_with_deps");
    let tag = reader.u8()?;
    if tag != TYPE_EVENT_WITH_DEPS {
        return Err("unknown event type".to_string());
    }
    let timestamp = reader.u64()?;
    let dep_count = reader.u8()? as usize;
    if dep_count > MAX_DEPS {
        return Err("event_with_deps dependency count exceeds fixed fields".to_string());
    }

    let mut dependencies = Vec::with_capacity(dep_count);
    for idx in 0..MAX_DEPS {
        let dep = reader.id()?;
        if idx < dep_count {
            dependencies.push(dep);
        } else if dep != [0; 32] {
            return Err("event_with_deps unused dependency field is nonzero".to_string());
        }
    }

    let payload = reader.bytes(PAYLOAD_BYTES)?;
    reader.finish()?;
    let mut fixed_payload = [0; PAYLOAD_BYTES];
    fixed_payload.copy_from_slice(&payload);

    Ok(EventWithDeps {
        timestamp,
        dependencies,
        payload: fixed_payload,
    })
}

pub fn encode_staged(event: &StagedEventWithDeps) -> Vec<u8> {
    assert_eq!(
        event.inner_bytes.len(),
        ENCODED_BYTES,
        "staged event_with_deps bytes must be fixed width"
    );
    let mut out = Writer::with_capacity(STAGED_ENCODED_BYTES);
    out.u8(TYPE_STAGED_EVENT_WITH_DEPS);
    out.u64(event.index);
    out.raw(&event.inner_bytes);
    out.finish()
}

pub fn decode_staged(bytes: &[u8]) -> Result<StagedEventWithDeps, String> {
    if bytes.len() != STAGED_ENCODED_BYTES {
        return Err("staged event_with_deps length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes, "staged event_with_deps");
    let tag = reader.u8()?;
    if tag != TYPE_STAGED_EVENT_WITH_DEPS {
        return Err("unknown staged event_with_deps type".to_string());
    }
    let index = reader.u64()?;
    let inner_bytes = reader.bytes(ENCODED_BYTES)?;
    reader.finish()?;
    record_from_bytes(inner_bytes.clone())?;
    Ok(StagedEventWithDeps { index, inner_bytes })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let decoded = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: decoded.timestamp,
        body_len: PAYLOAD_BYTES,
        canonical_bytes: bytes,
        dependencies: decoded.dependencies,
        workspace_id: None,
        scope: EventScope::Shared,
    })
}

pub fn staged_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    decode_staged(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: ENCODED_BYTES,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        workspace_id: None,
        scope: EventScope::Local,
    })
}

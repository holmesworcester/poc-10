//! Codec for compare sync events.
//!
//! A compare event carries one connection id and a fixed array of bucket
//! summaries. It is a real connection-scoped transient event, not a nested
//! packet item.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::super::types::SyncDirection;
use super::types::{BucketSummary, CompareEvent, BUCKETS};

pub const TYPE_SYNC_COMPARE: u8 = 140;
pub const ENCODED_BYTES: usize = 1 + 1 + 32 + BUCKETS * (8 + 32);

pub fn encode(event: &CompareEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(ENCODED_BYTES);
    out.u8(TYPE_SYNC_COMPARE);
    out.u8(event.direction.as_u8());
    out.id(&event.connection_id);
    for bucket in &event.summary {
        out.u64(bucket.count);
        out.id(&bucket.fingerprint);
    }
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<CompareEvent, String> {
    if bytes.len() != ENCODED_BYTES {
        return Err("sync compare length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes, "sync compare");
    let tag = reader.u8()?;
    if tag != TYPE_SYNC_COMPARE {
        return Err("unknown sync compare event".to_string());
    }
    let direction = SyncDirection::from_u8(reader.u8()?)?;
    let connection_id = reader.id()?;
    let mut summary = [BucketSummary::default(); BUCKETS];
    for bucket in &mut summary {
        bucket.count = reader.u64()?;
        bucket.fingerprint = reader.id()?;
    }
    reader.finish()?;
    Ok(CompareEvent {
        direction,
        connection_id,
        summary,
    })
}

pub fn is_event(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TYPE_SYNC_COMPARE)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        scope: EventScope::Transient,
    })
}

pub fn outbound_record(event: CompareEvent) -> Result<EventRecord, String> {
    record_from_bytes(encode(&event))
}

pub fn inbound_record_from_wire(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let mut event = decode(&bytes)?;
    if event.direction != SyncDirection::Outbound {
        return Err("received sync compare was not outbound".to_string());
    }
    event.direction = SyncDirection::Inbound;
    record_from_bytes(encode(&event))
}

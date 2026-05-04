use crate::core::store::{EventRecord, EventScope};
use crate::core::wire::{Reader, Writer};

use super::types::ContentEvent;

pub const TYPE_CONTENT: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentMetadata {
    timestamp: u64,
    payload_len: usize,
}

pub fn encode(event: &ContentEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 8 + 4 + event.payload.len());
    out.u8(TYPE_CONTENT);
    out.u64(event.timestamp);
    out.sized_bytes(&event.payload);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<ContentEvent, String> {
    let mut reader = Reader::new(bytes, "content event");
    let tag = reader.u8()?;
    if tag != TYPE_CONTENT {
        return Err("unknown event type".to_string());
    }
    let timestamp = reader.u64()?;
    let payload = reader.sized_bytes()?;
    reader.finish()?;
    Ok(ContentEvent { timestamp, payload })
}

pub fn validate(bytes: &[u8]) -> Result<(), String> {
    metadata(bytes).map(|_| ())
}

fn metadata(bytes: &[u8]) -> Result<ContentMetadata, String> {
    let mut reader = Reader::new(bytes, "content event");
    let tag = reader.u8()?;
    if tag != TYPE_CONTENT {
        return Err("unknown event type".to_string());
    }
    let timestamp = reader.u64()?;
    let payload = reader.sized_slice()?;
    let len = payload.len();
    reader.finish()?;

    Ok(ContentMetadata {
        timestamp,
        payload_len: len,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let metadata = metadata(&bytes)?;
    Ok(EventRecord {
        timestamp: metadata.timestamp,
        body_len: metadata.payload_len,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        scope: EventScope::Shared,
    })
}

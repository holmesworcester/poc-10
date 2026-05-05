//! Codec for shared content events.
//!
//! Content events are intentionally small in meaning and large in bytes. The
//! codec extracts timestamp and payload length without requiring projection to
//! understand payload contents. That keeps sync performance tests honest: bytes
//! are real event bytes, not side-channel fixtures.

use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::ContentEvent;

pub const TYPE_CONTENT: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentMetadata {
    workspace_id: EventId,
    timestamp: u64,
    payload_len: usize,
}

pub fn encode(event: &ContentEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 8 + 4 + event.payload.len());
    out.u8(TYPE_CONTENT);
    out.id(&event.workspace_id);
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
    let workspace_id = reader.id()?;
    let timestamp = reader.u64()?;
    let payload = reader.sized_bytes()?;
    reader.finish()?;
    Ok(ContentEvent {
        workspace_id,
        timestamp,
        payload,
    })
}

pub fn validate(bytes: &[u8]) -> Result<(), String> {
    metadata(bytes).map(|_| ())
}

fn metadata(bytes: &[u8]) -> Result<ContentMetadata, String> {
    // Metadata parsing validates the full record but avoids allocating the
    // payload, which is useful when building the common event header.
    let mut reader = Reader::new(bytes, "content event");
    let tag = reader.u8()?;
    if tag != TYPE_CONTENT {
        return Err("unknown event type".to_string());
    }
    let workspace_id = reader.id()?;
    let timestamp = reader.u64()?;
    let payload = reader.sized_slice()?;
    let len = payload.len();
    reader.finish()?;

    Ok(ContentMetadata {
        workspace_id,
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
        dependencies: vec![metadata.workspace_id],
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
        receive: None,
    })
}

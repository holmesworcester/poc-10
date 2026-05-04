use crate::core::store::{EventRecord, EventScope};

use super::types::ContentEvent;

pub const TYPE_CONTENT: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentMetadata {
    timestamp: u64,
    payload_len: usize,
}

pub fn encode(event: &ContentEvent) -> Vec<u8> {
    let len = u32::try_from(event.payload.len()).expect("content payload too large");
    let mut out = Vec::with_capacity(1 + 8 + 4 + event.payload.len());
    out.push(TYPE_CONTENT);
    out.extend_from_slice(&event.timestamp.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&event.payload);
    out
}

pub fn decode(bytes: &[u8]) -> Result<ContentEvent, String> {
    let metadata = metadata(bytes)?;
    Ok(ContentEvent {
        timestamp: metadata.timestamp,
        payload: bytes[13..].to_vec(),
    })
}

pub fn validate(bytes: &[u8]) -> Result<(), String> {
    metadata(bytes).map(|_| ())
}

fn metadata(bytes: &[u8]) -> Result<ContentMetadata, String> {
    if bytes.len() < 13 {
        return Err("content event is truncated".to_string());
    }
    if bytes[0] != TYPE_CONTENT {
        return Err("unknown event type".to_string());
    }

    let mut timestamp = [0u8; 8];
    timestamp.copy_from_slice(&bytes[1..9]);
    let timestamp = u64::from_be_bytes(timestamp);

    let mut len = [0u8; 4];
    len.copy_from_slice(&bytes[9..13]);
    let len = u32::from_be_bytes(len) as usize;
    if bytes.len() != 13 + len {
        return Err("content event length mismatch".to_string());
    }

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

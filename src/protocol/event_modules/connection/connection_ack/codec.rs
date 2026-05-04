//! Wire codec for connection ack events.
//!
//! Acks use the same connection magic as requests and remain transient. Their
//! body binds the accepting endpoint, the requester endpoint, the original
//! request id, and the derived connection id into one fixed-width record.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::super::types::EVENT_MAGIC;
use super::types::AckEvent;

pub const TAG: u8 = 2;

pub fn encode(event: &AckEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(10 + 1 + 32 * 4);
    out.raw(EVENT_MAGIC);
    out.u8(TAG);
    out.id(&event.from_endpoint);
    out.id(&event.to_endpoint);
    out.id(&event.request_id);
    out.id(&event.connection_id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<AckEvent, String> {
    if !bytes.starts_with(EVENT_MAGIC) {
        return Err("not a connection event".to_string());
    }
    let mut reader = Reader::new(&bytes[EVENT_MAGIC.len()..], "connection ack");
    let tag = reader.u8()?;
    if tag != TAG {
        return Err("expected connection ack".to_string());
    }
    let event = AckEvent {
        from_endpoint: reader.id()?,
        to_endpoint: reader.id()?,
        request_id: reader.id()?,
        connection_id: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn is_ack(bytes: &[u8]) -> bool {
    bytes.starts_with(EVENT_MAGIC) && bytes.get(EVENT_MAGIC.len()) == Some(&TAG)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        scope: EventScope::Transient,
        receive: None,
    })
}

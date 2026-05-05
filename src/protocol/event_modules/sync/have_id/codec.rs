//! Codec for have-id sync events.
//!
//! A have-id event advertises one event id at one timestamp. It is cheap to
//! duplicate and cheap to dedupe, and it has its own event id before transit
//! wrapping.

use crate::protocol::event_modules::types::{ConnectionScope, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::HaveIdEvent;

pub const TYPE_SYNC_HAVE_ID: u8 = 141;
pub const ENCODED_BYTES: usize = 1 + 32 + 8 + 32;

pub fn encode(event: &HaveIdEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(ENCODED_BYTES);
    out.u8(TYPE_SYNC_HAVE_ID);
    out.id(&event.connection_id);
    out.u64(event.timestamp);
    out.id(&event.id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<HaveIdEvent, String> {
    if bytes.len() != ENCODED_BYTES {
        return Err("sync have-id length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes, "sync have-id");
    let tag = reader.u8()?;
    if tag != TYPE_SYNC_HAVE_ID {
        return Err("unknown sync have-id event".to_string());
    }
    let event = HaveIdEvent {
        connection_id: reader.id()?,
        timestamp: reader.u64()?,
        id: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn is_event(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TYPE_SYNC_HAVE_ID)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    record_with_scope(
        bytes,
        EventScope::Connection(ConnectionScope::Outgoing {
            connection_id: event.connection_id,
        }),
    )
}

fn record_with_scope(bytes: Vec<u8>, scope: EventScope) -> Result<EventRecord, String> {
    decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        scope,
        receive: None,
    })
}

pub fn outbound_record(event: HaveIdEvent) -> Result<EventRecord, String> {
    let bytes = encode(&event);
    record_with_scope(
        bytes,
        EventScope::Connection(ConnectionScope::Outgoing {
            connection_id: event.connection_id,
        }),
    )
}

pub fn inbound_record_from_wire(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    record_with_scope(
        bytes,
        EventScope::Connection(ConnectionScope::Incoming {
            connection_id: event.connection_id,
        }),
    )
}

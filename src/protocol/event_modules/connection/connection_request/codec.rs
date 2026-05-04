use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::super::types::EVENT_MAGIC;
use super::types::RequestEvent;

pub const TAG: u8 = 1;

pub fn encode(event: &RequestEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(10 + 1 + 32 * 3);
    out.raw(EVENT_MAGIC);
    out.u8(TAG);
    out.id(&event.from_endpoint);
    out.id(&event.nonce);
    out.id(&event.bootstrap_hash);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<RequestEvent, String> {
    if !bytes.starts_with(EVENT_MAGIC) {
        return Err("not a connection event".to_string());
    }
    let mut reader = Reader::new(&bytes[EVENT_MAGIC.len()..], "connection request");
    let tag = reader.u8()?;
    if tag != TAG {
        return Err("expected connection request".to_string());
    }
    let event = RequestEvent {
        from_endpoint: reader.id()?,
        nonce: reader.id()?,
        bootstrap_hash: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn is_request(bytes: &[u8]) -> bool {
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
    })
}

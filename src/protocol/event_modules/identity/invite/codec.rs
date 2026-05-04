use crate::core::store::{EventRecord, EventScope};
use crate::core::wire::{Reader, Writer};

use super::types::InviteSecretEvent;

pub const TYPE_INVITE_SECRET: u8 = 129;

pub fn encode(event: &InviteSecretEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 32);
    out.u8(TYPE_INVITE_SECRET);
    out.id(&event.bootstrap_hash);
    out.id(&event.bootstrap_secret);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<InviteSecretEvent, String> {
    let mut reader = Reader::new(bytes, "invite secret");
    let tag = reader.u8()?;
    if tag != TYPE_INVITE_SECRET {
        return Err("expected invite secret".to_string());
    }
    let event = InviteSecretEvent {
        bootstrap_hash: reader.id()?,
        bootstrap_secret: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        scope: EventScope::Local,
    })
}

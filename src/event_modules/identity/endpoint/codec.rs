use x25519_dalek::{PublicKey, StaticSecret};

use crate::store::{EventRecord, EventScope};
use crate::wire::{Reader, Writer};

use super::types::EndpointKeypair;

pub const TYPE_LOCAL_ENDPOINT: u8 = 128;

pub fn encode(event: &EndpointKeypair) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 32);
    out.u8(TYPE_LOCAL_ENDPOINT);
    out.id(&event.endpoint);
    out.id(&event.secret);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<EndpointKeypair, String> {
    let mut reader = Reader::new(bytes, "local endpoint");
    let tag = reader.u8()?;
    if tag != TYPE_LOCAL_ENDPOINT {
        return Err("expected local endpoint".to_string());
    }
    let endpoint = reader.id()?;
    let secret = reader.id()?;
    reader.finish()?;
    let derived = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
    if derived != endpoint {
        return Err("local endpoint secret does not match endpoint".to_string());
    }
    Ok(EndpointKeypair { endpoint, secret })
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

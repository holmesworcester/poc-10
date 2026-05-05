//! Codec for the local endpoint event.
//!
//! The event stores the endpoint public key and local secret as a local-only
//! fact. Decoding re-derives the public key from the secret, so corrupted or
//! mismatched identity rows fail before projection.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

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
        workspace_id: None,
        scope: EventScope::Local,
        receive: None,
    })
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint::commands;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn decode_rejects_endpoint_that_does_not_match_secret() {
        let good = commands::create_local_keypair().value;
        let bad = commands::create_local_keypair().value;
        let bytes = encode(&EndpointKeypair {
            endpoint: good.endpoint,
            secret: bad.secret,
        });

        let err = decode(&bytes).expect_err("mismatched endpoint must fail");

        assert_eq!(err, "local endpoint secret does not match endpoint");
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&commands::create_local_keypair().value);
        bytes.push(0);

        let err = decode(&bytes).expect_err("trailing byte must fail");

        assert!(err.starts_with("trailing "), "{err}");
    }

    #[test]
    fn record_from_bytes_marks_endpoint_local_only() {
        let bytes = encode(&commands::create_local_keypair().value);
        let record = record_from_bytes(bytes).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
    }
}

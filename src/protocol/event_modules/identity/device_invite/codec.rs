//! Codec for shared device-invite events.
//!
//! The fixed-width format is:
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32)
//! || user_authority_event_id(32) || invite_public_key(32)
//! ```

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::DeviceInviteEvent;

pub const TYPE_DEVICE_INVITE: u8 = 134;
pub const DEVICE_INVITE_WIRE_SIZE: usize = 1 + 8 + 32 + 32 + 32;

pub fn encode(event: &DeviceInviteEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(DEVICE_INVITE_WIRE_SIZE);
    out.u8(TYPE_DEVICE_INVITE);
    out.u64(event.created_at_ms);
    out.id(&event.workspace_id);
    out.id(&event.user_authority_event_id);
    out.id(&event.public_key);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<DeviceInviteEvent, String> {
    let mut reader = Reader::new(bytes, "device invite");
    let tag = reader.u8()?;
    if tag != TYPE_DEVICE_INVITE {
        return Err("expected device invite".to_string());
    }
    let event = DeviceInviteEvent {
        created_at_ms: reader.u64()?,
        workspace_id: reader.id()?,
        user_authority_event_id: reader.id()?,
        public_key: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: event.created_at_ms,
        body_len: DEVICE_INVITE_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies: vec![event.workspace_id, event.user_authority_event_id],
        scope: EventScope::Shared,
        receive: None,
    })
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn event() -> DeviceInviteEvent {
        DeviceInviteEvent {
            created_at_ms: 11,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            public_key: [3; 32],
        }
    }

    #[test]
    fn roundtrips_fixed_width_device_invite_event() {
        let encoded = encode(&event());

        assert_eq!(encoded.len(), DEVICE_INVITE_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode device invite"), event());
    }

    #[test]
    fn rejects_wrong_type_and_trailing_bytes() {
        let mut encoded = encode(&event());
        encoded[0] = 0xff;
        assert_eq!(
            decode(&encoded).expect_err("wrong type must fail"),
            "expected device invite"
        );

        let mut encoded = encode(&event());
        encoded.push(0);
        let err = decode(&encoded).expect_err("trailing byte must fail");
        assert!(err.starts_with("trailing "), "{err}");
    }

    #[test]
    fn record_is_shared_and_depends_on_workspace_and_user_authority() {
        let encoded = encode(&event());
        let record = record_from_bytes(encoded.clone()).expect("record");

        assert_eq!(record.timestamp, 11);
        assert_eq!(record.body_len, DEVICE_INVITE_WIRE_SIZE - 1);
        assert_eq!(record.canonical_bytes, encoded);
        assert_eq!(record.dependencies, vec![[1; 32], [2; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }
}

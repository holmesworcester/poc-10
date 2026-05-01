//! `peer_secret` event module — local PeerSecret event used to materialize
//! transport identities.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse +
//! registry meta; `projector.rs` owns `ensure_schema` + the pure projector.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    encode_peer_secret, parse_peer_secret, PeerSecretEvent, PEER_SECRET_FIELDS, PEER_SECRET_META,
    PEER_SECRET_WIRE_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event, EventError, ParsedEvent};
    use crate::event_modules::EVENT_TYPE_PEER_SECRET;

    #[test]
    fn test_roundtrip_peer_secret() {
        let e = PeerSecretEvent {
            created_at_ms: 1234567890123,
            workspace_id: [3u8; 32],
            signer_event_id: [1u8; 32],
            private_key_bytes: [2u8; 32],
        };
        let event = ParsedEvent::PeerSecret(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), PEER_SECRET_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_reject_trailing_data() {
        let e = PeerSecretEvent {
            created_at_ms: 100,
            workspace_id: [0u8; 32],
            signer_event_id: [0u8; 32],
            private_key_bytes: [0u8; 32],
        };
        let event = ParsedEvent::PeerSecret(e);
        let mut blob = encode_event(&event).unwrap();
        blob.push(0xFF);
        let err = parse_event(&blob).unwrap_err();
        assert!(matches!(
            err,
            EventError::TrailingData {
                expected: PEER_SECRET_WIRE_SIZE,
                actual: 106
            }
        ));
    }

    #[test]
    fn test_reject_short_data() {
        let blob = vec![EVENT_TYPE_PEER_SECRET; 10];
        let err = parse_event(&blob).unwrap_err();
        assert!(matches!(
            err,
            EventError::TooShort {
                expected: PEER_SECRET_WIRE_SIZE,
                ..
            }
        ));
    }
}

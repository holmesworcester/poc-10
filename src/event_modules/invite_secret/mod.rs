//! `invite_secret` event module — local secret material for an invite identity.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse +
//! deterministic event id helpers + registry meta; `projector.rs` owns
//! `ensure_schema` + the pure projector.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    deterministic_invite_secret_created_at_ms, deterministic_invite_secret_event,
    deterministic_invite_secret_event_id, encode_invite_secret, parse_invite_secret,
    InviteSecretEvent, INVITE_SECRET_FIELDS, INVITE_SECRET_META, INVITE_SECRET_WIRE_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event, ParsedEvent};

    #[test]
    fn test_roundtrip_invite_secret() {
        let e = ParsedEvent::InviteSecret(InviteSecretEvent {
            created_at_ms: 12345,
            invite_event_id: [9u8; 32],
            workspace_id: [3u8; 32],
            private_key_bytes: [7u8; 32],
        });
        let blob = encode_event(&e).unwrap();
        assert_eq!(blob.len(), INVITE_SECRET_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn test_deterministic_invite_secret_event_id_stable() {
        let invite = [7u8; 32];
        let workspace = [3u8; 32];
        let key = [11u8; 32];
        let a = deterministic_invite_secret_event_id(&invite, &workspace, &key);
        let b = deterministic_invite_secret_event_id(&invite, &workspace, &key);
        assert_eq!(a, b);
    }
}

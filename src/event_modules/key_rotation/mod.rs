//! `key_rotation` event module — DAG-frontier-anchored content-key rotation.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse +
//! registry meta; `projector.rs` owns `ensure_schema` + the pure projector
//! (which uses the frontier helpers re-exported from `removal`).
//!
//! TODO(plan.md Wave 2): Wave-1 deferred drop — entangled with identity /
//! transport. Migrated to per-file layout per the plan anyway since the
//! event still exists.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    encode_key_rotation, parse_key_rotation, KeyRotationEvent, KEY_ROTATION_FIELDS,
    KEY_ROTATION_META, KEY_ROTATION_WIRE_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::removal::frontier_hash_from_refs;
    use crate::event_modules::{encode_event, parse_event, ParsedEvent};

    #[test]
    fn test_key_rotation_roundtrip() {
        let frontier_refs = vec![[0x11; 32]];
        let event = ParsedEvent::KeyRotation(KeyRotationEvent {
            created_at_ms: 10_000,
            workspace_id: [0x99; 32],
            key_event_id: [0x22; 32],
            frontier_count: frontier_refs.len() as u8,
            frontier_ref_1: frontier_refs[0],
            frontier_ref_2: [0u8; 32],
            frontier_ref_3: [0u8; 32],
            frontier_ref_4: [0u8; 32],
            frontier_hash: frontier_hash_from_refs(&frontier_refs),
            rotated_by: [0x33; 32],
            signed_by: [0x33; 32],
            signer_type: 5,
            signature: [0x44; 64],
        });
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), KEY_ROTATION_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }
}

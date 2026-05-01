//! `removal` event module — DAG-frontier-anchored member removal event.
//!
//! Per-file layout (plan.md per-file rule): `codec.rs` owns encode/parse,
//! frontier helpers (used by `key_rotation` and `key_shared`), and the
//! registry meta. `projector.rs` owns `ensure_schema` + the pure projector.

pub mod projector;
pub mod codec;

pub use projector::{ensure_schema, project_pure};
pub use codec::{
    canonicalize_frontier_refs, encode_removal, frontier_hash_from_refs, frontier_refs_from_slots,
    parse_removal, validate_canonical_frontier_refs, RemovalEvent, MAX_REMOVAL_FRONTIER_REFS,
    REMOVAL_FIELDS, REMOVAL_META, REMOVAL_WIRE_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{encode_event, parse_event, ParsedEvent};

    #[test]
    fn test_removal_roundtrip() {
        let frontier_refs = vec![[0x11; 32], [0x22; 32]];
        let event = ParsedEvent::Removal(RemovalEvent {
            created_at_ms: 9_000,
            workspace_id: [0xAA; 32],
            removed_member_ref: [0x33; 32],
            parent_count: frontier_refs.len() as u8,
            parent_1: frontier_refs[0],
            parent_2: frontier_refs[1],
            parent_3: [0u8; 32],
            parent_4: [0u8; 32],
            frontier_hash: frontier_hash_from_refs(&frontier_refs),
            removed_by: [0x44; 32],
            signed_by: [0x44; 32],
            signer_type: 5,
            signature: [0x55; 64],
        });
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), REMOVAL_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_frontier_hash_is_order_independent_for_multi_parent_frontier() {
        let a = [0x11; 32];
        let b = [0x22; 32];
        let c = [0x33; 32];

        let left = frontier_hash_from_refs(&[a, b, c]);
        let right = frontier_hash_from_refs(&[c, a, b]);

        assert_eq!(
            left, right,
            "multi-parent frontier hash should converge independent of parent order"
        );
    }
}

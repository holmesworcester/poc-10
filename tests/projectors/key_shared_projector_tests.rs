//! Pure projector conformance tests for KeyShared (type 22).
//!
//! Plan.md (Forking plan, "no scaffolding"): the projector reads only
//! `{event, deps, labels}`. The legacy DH-unwrap path that consumed
//! `ctx.unwrapped_secret_material` to emit a deterministic KeySecret
//! has been removed; tests of that scaffolding are deleted.
//!
//! Coverage:
//!   SPEC_KS_FRONTIER_01 — carried frontier hash matches declared frontier refs
//!   SPEC_KS_DELIVERY_01 — carried delivery_target_id matches deterministic hash

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::key_request::delivery_target_id;
    use topo::event_modules::key_shared::{project_pure, KeySharedEvent};
    use topo::event_modules::removal::frontier_hash_from_refs;
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::ContextSnapshot;

    const TEST_WORKSPACE_ID: [u8; 32] = [0x77u8; 32];

    fn make_key_shared(
        key_event_id: [u8; 32],
        frontier_count: u8,
        frontier_ref_1: [u8; 32],
        frontier_ref_2: [u8; 32],
        frontier_hash: [u8; 32],
        delivery_target_id: [u8; 32],
    ) -> ParsedEvent {
        ParsedEvent::KeyShared(KeySharedEvent {
            created_at_ms: 6000,
            workspace_id: TEST_WORKSPACE_ID,
            key_event_id,
            frontier_count,
            frontier_ref_1,
            frontier_ref_2,
            frontier_ref_3: [0u8; 32],
            frontier_ref_4: [0u8; 32],
            frontier_hash,
            delivery_target_id,
            recipient_event_id: [2u8; 32],
            unwrap_key_event_id: [3u8; 32],
            wrapped_key: [3u8; 32],
            signed_by: [4u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_key_shared_valid() {
        let key_event_id = [42u8; 32];
        let frontier_hash = frontier_hash_from_refs(&[]);
        let parsed = make_key_shared(
            key_event_id,
            0,
            [0u8; 32],
            [0u8; 32],
            frontier_hash,
            delivery_target_id(&key_event_id, &frontier_hash, &[2u8; 32], &[3u8; 32]),
        );
        let event_id = b64(&[9u8; 32]);

        let result = project_pure(&event_id, &parsed, &ContextSnapshot::default());
        assert_valid(&result);
        assert_writes_to_table(&result, "key_shared");
    }

    #[test]
    fn test_key_shared_rejects_delivery_target_mismatch() {
        let parsed = make_key_shared(
            [42u8; 32],
            0,
            [0u8; 32],
            [0u8; 32],
            frontier_hash_from_refs(&[]),
            [8u8; 32],
        );
        let event_id = b64(&[6u8; 32]);

        let result = project_pure(&event_id, &parsed, &ContextSnapshot::default());
        assert_reject_contains(
            &result,
            "delivery_target_id does not match key_shared target",
        );
    }

    #[test]
    fn test_key_shared_rejects_frontier_hash_mismatch() {
        let key_event_id = [42u8; 32];
        let parsed = make_key_shared(
            key_event_id,
            1,
            [0xAA; 32],
            [0u8; 32],
            [0xBB; 32],
            delivery_target_id(&key_event_id, &[0xBB; 32], &[2u8; 32], &[3u8; 32]),
        );
        let event_id = b64(&[5u8; 32]);

        let result = project_pure(&event_id, &parsed, &ContextSnapshot::default());
        assert_reject_contains(&result, "frontier_hash does not match key_shared frontier");
    }

    #[test]
    fn test_key_shared_valid_multi_parent_frontier() {
        let key_event_id = [42u8; 32];
        let frontier_hash = frontier_hash_from_refs(&[[0xAA; 32], [0xBB; 32]]);
        let parsed = make_key_shared(
            key_event_id,
            2,
            [0xAA; 32],
            [0xBB; 32],
            frontier_hash,
            delivery_target_id(&key_event_id, &frontier_hash, &[2u8; 32], &[3u8; 32]),
        );
        let event_id = b64(&[4u8; 32]);

        let result = project_pure(&event_id, &parsed, &ContextSnapshot::default());
        assert_valid(&result);
        assert_writes_to_table(&result, "key_shared");
    }

    #[test]
    fn test_key_shared_rejects_unsorted_multi_parent_frontier_refs() {
        let key_event_id = [42u8; 32];
        let frontier_hash = frontier_hash_from_refs(&[[0xAA; 32], [0xBB; 32]]);
        let parsed = make_key_shared(
            key_event_id,
            2,
            [0xBB; 32],
            [0xAA; 32],
            frontier_hash,
            delivery_target_id(&key_event_id, &frontier_hash, &[2u8; 32], &[3u8; 32]),
        );
        let event_id = b64(&[3u8; 32]);

        let result = project_pure(&event_id, &parsed, &ContextSnapshot::default());
        assert_reject_contains(&result, "frontier refs must be sorted in canonical order");
    }
}

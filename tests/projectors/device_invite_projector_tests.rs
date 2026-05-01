//! Pure projector conformance tests for DeviceInvite (type 12).
//!
//! Plan.md Stage 3.5 step 5B — `device_invites.recorded_by` shadow column
//! dropped; the projector reads only `{event, deps, labels}`.

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::peer_invite_shared::project_pure;
    use topo::event_modules::peer_invite_shared::DeviceInviteEvent;
    use topo::event_modules::ParsedEvent;

    fn make_device_invite(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 9000,
            public_key,
            workspace_id: [4u8; 32],
            authority_event_id: [3u8; 32],
            signed_by: [3u8; 32],
            signer_type: 4,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_device_invite_basic_valid() {
        let parsed = make_device_invite([5u8; 32]);
        let ctx = empty_ctx();
        let event_id = b64(&[11u8; 32]);

        let result = project_pure(&event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "device_invites");
    }

    #[test]
    fn test_device_invite_rejects_non_device_invite_event() {
        let parsed = ParsedEvent::KeySecret(topo::event_modules::key_secret::KeySecretEvent {
            created_at_ms: 1,
            workspace_id: [0u8; 32],
            key_bytes: [1u8; 32],
        });
        let event_id = b64(&[13u8; 32]);
        let result = project_pure(&event_id, &parsed, &empty_ctx());
        assert_reject(&result);
    }
}

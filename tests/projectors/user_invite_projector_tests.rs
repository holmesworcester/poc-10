//! Pure projector conformance tests for UserInvite (type 10).
//!
//! Plan.md Stage 3.5 step 5B — `user_invites.recorded_by` shadow column
//! dropped; the projector reads only `{event, deps, labels}`.

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::user_invite_shared::project_pure;
    use topo::event_modules::user_invite_shared::UserInviteEvent;
    use topo::event_modules::ParsedEvent;

    fn make_user_invite(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 8000,
            public_key,
            workspace_id: [10u8; 32],
            authority_event_id: [10u8; 32],
            signed_by: [10u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_user_invite_basic_valid() {
        let parsed = make_user_invite([5u8; 32]);
        let ctx = empty_ctx();
        let event_id = b64(&[3u8; 32]);

        let result = project_pure(&event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "user_invites");
    }

    #[test]
    fn test_user_invite_rejects_non_user_invite_event() {
        let parsed = ParsedEvent::KeySecret(topo::event_modules::key_secret::KeySecretEvent {
            created_at_ms: 1,
            workspace_id: [0u8; 32],
            key_bytes: [1u8; 32],
        });
        let event_id = b64(&[4u8; 32]);
        let result = project_pure(&event_id, &parsed, &empty_ctx());
        assert_reject(&result);
    }
}

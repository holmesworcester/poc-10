//! Pure projector conformance tests for InviteAccepted (type 9).
//!
//! Plan.md Stage 3.5 step 5B — `invites_accepted.recorded_by` shadow column
//! dropped; the projector reads only `{event, deps, labels}`. The
//! bootstrap-trust write side has been removed from the projector and is now
//! the responsibility of the local authoring-side codepath.

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::invite_accepted::{project_pure, InviteAcceptedEvent};
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::EmitCommand;

    fn make_invite_accepted(invite_id: [u8; 32], workspace_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: 2000,
            tenant_event_id: [7u8; 32],
            invite_event_id: invite_id,
            workspace_id,
        })
    }

    #[test]
    fn test_invite_accepted_writes_workspace_binding() {
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted([5u8; 32], ws_id);
        let ctx = empty_ctx();

        let result = project_pure("event_ia_1", &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "invites_accepted");
    }

    #[test]
    fn test_invite_accepted_emits_retry_workspace_event() {
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted([5u8; 32], ws_id);
        let ctx = empty_ctx();

        let result = project_pure("event_ia_2", &parsed, &ctx);
        assert_valid(&result);
        assert_emits_command(&result, "RetryWorkspaceEvent", |c| {
            matches!(c, EmitCommand::RetryWorkspaceEvent { .. })
        });
    }
}

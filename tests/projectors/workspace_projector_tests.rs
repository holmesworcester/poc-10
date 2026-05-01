//! Pure projector conformance tests for Workspace (type 8).
//!
//! Updated for plan.md Stage 2: the workspace projector no longer
//! consults `accepted_workspace_id` — it derives `workspace_id` from
//! the event itself. Trust-anchor rejection is replaced by the
//! generic label-gate pattern (a `deleted` / `removed_by:*` label on
//! the event id rejects projection).
//!
//! TLA+ guards retained:
//!   SPEC_WS_SINGLE_01 — InvSingleWorkspace (InsertOrIgnore idempotence)
//!   SPEC_WS_LABEL_01  — label-gated reject (deleted / removed_by)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::workspace::{project_pure, WorkspaceEvent};
    use topo::event_modules::ParsedEvent;

    const PEER: &str = "peer_alice";

    fn make_workspace(workspace_id: [u8; 32], public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 1000,
            workspace_id,
            public_key,
            name: "test-ws".to_string(),
        })
    }

    // ── Plan.md Stage 2: workspace applies cleanly with empty context ──

    #[test]
    fn test_workspace_applies_with_empty_context() {
        let ws_id = [1u8; 32];
        let ws_id_b64 = b64(&ws_id);
        let parsed = make_workspace(ws_id, [2u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(&ws_id_b64, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "workspaces");
        assert_no_commands(&result);
    }

    // ── SPEC_WS_LABEL_01: label-gated reject (deleted / removed_by) ──

    #[test]
    fn test_workspace_rejects_when_deleted_label_present() {
        let ws_id = [1u8; 32];
        let ws_id_b64 = b64(&ws_id);
        let parsed = make_workspace(ws_id, [2u8; 32]);
        let mut ctx = empty_ctx();
        ctx.labels
            .insert(ws_id_b64.clone(), vec!["deleted".to_string()]);

        let result = project_pure(&ws_id_b64, &parsed, &ctx);
        assert_reject_contains(&result, "label");
    }

    // ── SPEC_WS_SINGLE_01: pass (InsertOrIgnore ensures at-most-one) ──

    #[test]
    fn test_workspace_insert_or_ignore() {
        let ws_id = [1u8; 32];
        let ws_id_b64 = b64(&ws_id);
        let parsed = make_workspace(ws_id, [2u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(&ws_id_b64, &parsed, &ctx);
        assert_valid(&result);
        assert_eq!(result.write_ops.len(), 1);
        assert_writes_to_table(&result, "workspaces");
    }
}

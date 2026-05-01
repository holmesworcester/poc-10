use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: User -> users table.
///
/// New-chain rules (plan.md Stage 2 + round-9 step 5A):
/// - Read the explicit `workspace_id` field from the event (Phase 32).
/// - Apply the standard label-gate: any `removed_by:*` / `superseded` /
///   `deleted` label on this event id rejects the projection
///   (plan.md §164-170).
/// - Write to `users` keyed by `(workspace_id, event_id)`.
///
/// Plan.md round-9 step 5A: `recorded_by` shadow column dropped. The
/// projector no longer reads or writes it.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let user = match parsed {
        ParsedEvent::User(u) => u,
        _ => return ProjectorResult::reject("not a user event".to_string()),
    };

    if user.username.trim().is_empty() {
        return ProjectorResult::reject("username must not be empty".to_string());
    }

    // Generic label-gate (plan.md §164-170).
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!("user gated by label `{}`", t));
            }
        }
    }

    let workspace_id_b64 = event_id_to_base64(&user.workspace_id);

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "users",
        columns: vec![
            "event_id",
            "workspace_id",
            "public_key",
            "username",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(workspace_id_b64),
            SqlVal::Blob(user.public_key.to_vec()),
            SqlVal::Text(user.username.clone()),
        ],
    }];
    ProjectorResult::valid(ops)
}

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::event_modules::{ParsedEvent, UserEvent, WorkspaceEvent};

    fn user_event() -> ParsedEvent {
        ParsedEvent::User(UserEvent {
            created_at_ms: 1,
            workspace_id: [9u8; 32],
            public_key: [7u8; 32],
            username: "alice".to_string(),
            signed_by: [8u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_user_valid() {
        let result = project_pure(
            "user-event",
            &user_event(),
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Valid
        ));
        assert_eq!(result.write_ops.len(), 1);
    }

    #[test]
    fn test_user_rejects_non_user_event() {
        let other = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 1,
            workspace_id: [0u8; 32],
            public_key: [0u8; 32],
            name: "ws".to_string(),
        });
        let result = project_pure(
            "workspace-event",
            &other,
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Reject { .. }
        ));
    }
}

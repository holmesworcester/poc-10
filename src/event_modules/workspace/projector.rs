use crate::event_modules::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Workspace.
///
/// New-chain rules (plan.md Stage 2 + round-9 step 5A):
/// - Workspace events are roots — by convention, every other event in
///   the workspace points at this root via its own `workspace_id`
///   field, where `workspace_id` is the canonical event id of the root
///   (`BLAKE3(canonical_bytes)`). The projector therefore writes
///   `workspaces.workspace_id = event_id_b64` so the table key lines
///   up with what siblings/children carry.
/// - The `workspace_id` field on `WorkspaceEvent` itself is a
///   redundant self-reference: by invariant it equals
///   `BLAKE3(canonical_bytes)`. We tolerate any value at the field
///   level (a sender that sets it wrong still produces a valid
///   canonical event under our wire codec) but the projection table
///   key is always `event_id`. A future hardening pass can enforce
///   `ws.workspace_id == event_id` as a parse-time invariant.
/// - Apply the standard label-gate pattern: any `removed_by:*` /
///   `superseded` / `deleted` label on this event id rejects the
///   projection (plan.md §164-170).
/// - Write to `workspaces` keyed by `(workspace_id, event_id)`.
///
/// Plan.md round-9 step 5A: `recorded_by` shadow column dropped. The
/// projector no longer reads or writes it.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ws = match parsed {
        ParsedEvent::Workspace(w) => w,
        _ => return ProjectorResult::reject("not a workspace event".to_string()),
    };

    // Generic label-gate: a future "deleted" / "removed_by" label on this
    // event id retires the projection. `labels` is keyed by base64
    // event id (own_id ++ deps), populated by `load_generic_context`
    // (plan.md lines 234-240).
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "workspace gated by label `{}`",
                    t
                ));
            }
        }
    }

    // Suppress unused warning for the field's wire presence — a future
    // pass will enforce equality with event_id at parse time.
    let _ = ws.workspace_id;

    // The workspace_id we write to the projection table is the
    // event_id of the root workspace event. Children / siblings
    // reference workspaces by exactly this id (every other event's
    // `workspace_id` field is the BLAKE3 hash of this event's
    // canonical bytes), so the join works against `event_id` of the
    // root.
    let workspace_id_b64 = event_id_b64.to_string();

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "workspaces",
        columns: vec![
            "event_id",
            "workspace_id",
            "public_key",
            "name",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(workspace_id_b64),
            SqlVal::Blob(ws.public_key.to_vec()),
            SqlVal::Text(ws.name.clone()),
        ],
    }];
    ProjectorResult::valid(ops)
}

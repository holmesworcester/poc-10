use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// `invites_accepted` projection table.
///
/// Plan.md Stage 3.5 step 5B — drop the legacy `recorded_by` shadow
/// column. The PK is `(workspace_id, event_id)` (already migrated in
/// Stage 2); step 5B finishes the migration by removing the unused
/// shadow column and its index. Per-tenant queries against
/// `invites_accepted` resolve the caller's workspace_id from the
/// caller-side workspace binding and filter on `WHERE workspace_id = ?1`.
///
/// For poc-8 dev we DROP+CREATE on schema-init when the existing table
/// still carries the legacy `recorded_by` column or the wrong PK shape.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match table_state(conn, "invites_accepted")? {
        Some(state) => {
            state.pk != vec!["workspace_id".to_string(), "event_id".to_string()]
                || state.has_recorded_by
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS invites_accepted")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS invites_accepted (
            workspace_id TEXT,
            event_id TEXT NOT NULL,
            tenant_event_id TEXT NOT NULL,
            invite_event_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_invites_accepted_event_id
            ON invites_accepted(event_id);
        ",
    )?;
    Ok(())
}

struct TableState {
    pk: Vec<String>,
    has_recorded_by: bool,
}

fn table_state(conn: &Connection, table: &str) -> rusqlite::Result<Option<TableState>> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    let mut found_any = false;
    let mut pks: Vec<(i64, String)> = Vec::new();
    let mut has_recorded_by = false;
    while let Some(row) = rows.next()? {
        found_any = true;
        let name: String = row.get(1)?;
        let pk: i64 = row.get(5)?;
        if pk > 0 {
            pks.push((pk, name.clone()));
        }
        if name == "recorded_by" {
            has_recorded_by = true;
        }
    }
    if !found_any {
        return Ok(None);
    }
    pks.sort_by_key(|p| p.0);
    Ok(Some(TableState {
        pk: pks.into_iter().map(|p| p.1).collect(),
        has_recorded_by,
    }))
}

/// Pure projector: InviteAccepted — workspace-binding row + workspace retry.
///
/// Plan.md "no scaffolding" rule (Forking plan): the projector reads only
/// `{event, deps, labels}`. Validation rules:
///
/// - The event's own `workspace_id` field drives the projection-table key.
/// - Apply the standard label-gate pattern: any `removed_by:*` /
///   `superseded` / `deleted` label on this event id rejects the
///   projection (plan.md §164-170).
///
/// Bootstrap-trust materialization and transport-identity install were
/// previously gated on bespoke `bootstrap_context`, `is_local_create`,
/// `has_local_invite_secret`, and `peer_shared_transport_identity_active`
/// fields on the snapshot. Those legacy flags are gone — the runtime
/// never populated them on the new chain. The pure projector now writes
/// only the workspace-binding row and emits the workspace retry command;
/// any bootstrap-trust install is the responsibility of the local
/// authoring-side codepath (the daemon only PROJECTS events here).
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ia = match parsed {
        ParsedEvent::InviteAccepted(a) => a,
        _ => return ProjectorResult::reject("not an invite_accepted event".to_string()),
    };

    // Generic label-gate (plan.md §164-170): any retiring label on this
    // event id rejects the projection.
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "invite_accepted gated by label `{}`",
                    t
                ));
            }
        }
    }

    let invite_eid_b64 = event_id_to_base64(&ia.invite_event_id);
    let workspace_id_b64 = event_id_to_base64(&ia.workspace_id);

    let ops = vec![
        // Projection table — keyed by (workspace_id, event_id).
        WriteOp::InsertOrIgnore {
            table: "invites_accepted",
            columns: vec![
                "event_id",
                "workspace_id",
                "tenant_event_id",
                "invite_event_id",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(workspace_id_b64.clone()),
                SqlVal::Text(event_id_to_base64(&ia.tenant_event_id)),
                SqlVal::Text(invite_eid_b64),
                SqlVal::Int(ia.created_at_ms as i64),
            ],
        },
    ];

    let commands = vec![EmitCommand::RetryWorkspaceEvent {
        workspace_id: workspace_id_b64,
    }];

    ProjectorResult::valid_with_commands(ops, commands)
}

use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// `invite_secrets` projection table.
///
/// Plan.md Stage 3.5 step 5B — drop the legacy `recorded_by` shadow
/// column. The PK is `(workspace_id, event_id)` (already migrated in
/// Stage 2); step 5B finishes the migration by removing the unused
/// shadow column and its index. Per-tenant queries against
/// `invite_secrets` resolve the caller's workspace_id from the
/// caller-side workspace binding and filter on `WHERE workspace_id = ?1`,
/// or use `invite_event_id` directly (it is globally unique).
///
/// For poc-8 dev we DROP+CREATE on schema-init when the existing table
/// still carries the legacy `recorded_by` column or the wrong PK shape.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match table_state(conn, "invite_secrets")? {
        Some(state) => {
            state.pk != vec!["workspace_id".to_string(), "event_id".to_string()]
                || state.has_recorded_by
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS invite_secrets")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS invite_secrets (
            workspace_id TEXT,
            event_id TEXT NOT NULL,
            invite_event_id TEXT NOT NULL,
            private_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_invite_secrets_event_id
            ON invite_secrets(event_id);
        CREATE INDEX IF NOT EXISTS idx_invite_secrets_invite_event_id
            ON invite_secrets(invite_event_id);
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

/// Pure projector: InviteSecret -> invite_secrets table.
///
/// New-chain rules (plan.md Stage 3.5 step 5B):
/// - The event's own `workspace_id` field drives the projection-table
///   key — `recorded_by` is dropped from both PK and the row entirely.
/// - Apply the standard label-gate pattern: any retiring label on this
///   event id rejects the projection (plan.md §164-170).
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::InviteSecret(v) => v,
        _ => return ProjectorResult::reject("not an invite_secret event".to_string()),
    };

    // Generic label-gate (plan.md §164-170).
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "invite_secret gated by label `{}`",
                    t
                ));
            }
        }
    }

    // Plan.md Stage 3.5 step 5B: `recorded_by` shadow column dropped.
    // The projector no longer reads or writes it.

    let workspace_id_b64 = event_id_to_base64(&e.workspace_id);

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "invite_secrets",
        columns: vec![
            "event_id",
            "workspace_id",
            "invite_event_id",
            "private_key",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(event_id_to_base64(&e.invite_event_id)),
            SqlVal::Blob(e.private_key_bytes.to_vec()),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}

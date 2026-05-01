use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// `key_secrets` projection table.
///
/// Plan.md Stage 3.5 step 5C — drop the legacy `recorded_by` shadow
/// column. The PK is `(workspace_id, event_id)` (already migrated in
/// Stage 2); step 5C finishes the migration by removing the unused
/// shadow column and its index. Per-tenant queries against `key_secrets`
/// resolve the caller's workspace_id from `invites_accepted` and filter
/// on `WHERE workspace_id = ?1`.
///
/// For poc-8 dev we DROP+CREATE on schema-init when the existing table
/// either has the wrong PK shape or still carries the legacy
/// `recorded_by` column.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "key_secrets")? {
        Some(cols) => {
            cols != vec!["workspace_id".to_string(), "event_id".to_string()]
                || has_recorded_by(conn, "key_secrets")?
        }
        None => false, // table doesn't exist yet — create fresh below
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS key_secrets")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_secrets (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            key_bytes BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_key_secrets_event_id
            ON key_secrets(event_id);
        ",
    )?;
    Ok(())
}

/// Returns true if the table has a legacy `recorded_by` column.
fn has_recorded_by(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == "recorded_by" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn pk_columns(conn: &Connection, table: &str) -> rusqlite::Result<Option<Vec<String>>> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    let mut found_any = false;
    let mut pks: Vec<(i64, String)> = Vec::new();
    while let Some(row) = rows.next()? {
        found_any = true;
        let name: String = row.get(1)?;
        let pk: i64 = row.get(5)?;
        if pk > 0 {
            pks.push((pk, name));
        }
    }
    if !found_any {
        return Ok(None);
    }
    pks.sort_by_key(|p| p.0);
    Ok(Some(pks.into_iter().map(|p| p.1).collect()))
}

/// Pure projector: KeySecret -> key_secrets table insert.
///
/// New-chain rules (plan.md Stage 2):
/// - The event's own `workspace_id` field drives the projection-table
///   key — `recorded_by` is dropped from the PK.
/// - Apply the standard label-gate pattern: any retiring label on this
///   event id rejects the projection (plan.md §164-170).
///
/// Plan.md Stage 3.5 step 5C: the legacy `recorded_by` shadow column
/// has been dropped from the schema; the projector no longer reads or
/// writes it.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let sk = match parsed {
        ParsedEvent::KeySecret(s) => s,
        _ => return ProjectorResult::reject("not a key_secret event".to_string()),
    };

    // Generic label-gate (plan.md §164-170).
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "key_secret gated by label `{}`",
                    t
                ));
            }
        }
    }

    let workspace_id_b64 = event_id_to_base64(&sk.workspace_id);

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_secrets",
        columns: vec![
            "workspace_id",
            "event_id",
            "key_bytes",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(sk.key_bytes.to_vec()),
            SqlVal::Int(sk.created_at_ms as i64),
        ],
    }];
    ProjectorResult::valid(ops)
}

use super::super::ParsedEvent;
use super::codec::delivery_target_id;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// `key_requests` projection table.
///
/// Plan.md Stage 3.5 step 5C — drop the legacy `recorded_by` shadow
/// column. The PK is `(workspace_id, event_id)` (already migrated in
/// Stage 2); step 5C finishes the migration by removing the unused
/// shadow column and its index. Per-tenant queries against
/// `key_requests` resolve the caller's workspace_id from
/// `invites_accepted` and filter on `WHERE workspace_id = ?1`.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "key_requests")? {
        Some(cols) => {
            cols != vec!["workspace_id".to_string(), "event_id".to_string()]
                || has_recorded_by(conn, "key_requests")?
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS key_requests")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_requests (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            blocked_event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            delivery_target_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            unwrap_key_event_id TEXT NOT NULL,
            requester_signer_event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_key_requests_event_id
            ON key_requests(event_id);
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

pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let kr = match parsed {
        ParsedEvent::KeyRequest(v) => v,
        _ => return ProjectorResult::reject("not a key_request event".to_string()),
    };

    // Generic label-gate (plan.md §164-170).
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "key_request gated by label `{}`",
                    t
                ));
            }
        }
    }

    // Plan.md Stage 3.5 step 5C: `recorded_by` shadow column dropped.
    // The projector no longer reads or writes it.
    let expected_delivery_target_id = delivery_target_id(
        &kr.key_event_id,
        &kr.frontier_hash,
        &kr.recipient_event_id,
        &kr.unwrap_key_event_id,
    );
    if kr.delivery_target_id != expected_delivery_target_id {
        return ProjectorResult::reject(
            "delivery_target_id does not match key request target".to_string(),
        );
    }

    let workspace_id_b64 = event_id_to_base64(&kr.workspace_id);

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_requests",
        columns: vec![
            "workspace_id",
            "event_id",
            "blocked_event_id",
            "key_event_id",
            "frontier_hash",
            "delivery_target_id",
            "recipient_event_id",
            "unwrap_key_event_id",
            "requester_signer_event_id",
        ],
        values: vec![
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&kr.blocked_event_id)),
            SqlVal::Text(event_id_to_base64(&kr.key_event_id)),
            SqlVal::Text(event_id_to_base64(&kr.frontier_hash)),
            SqlVal::Text(event_id_to_base64(&kr.delivery_target_id)),
            SqlVal::Text(event_id_to_base64(&kr.recipient_event_id)),
            SqlVal::Text(event_id_to_base64(&kr.unwrap_key_event_id)),
            SqlVal::Text(event_id_to_base64(&kr.signed_by)),
        ],
    }];

    ProjectorResult::valid(ops)
}

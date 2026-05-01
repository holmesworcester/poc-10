use super::super::key_request::delivery_target_id;
use super::super::removal::{
    frontier_hash_from_refs, frontier_refs_from_slots, validate_canonical_frontier_refs,
};
use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// `key_shared` projection table.
///
/// Plan.md Stage 3.5 step 5C — drop the legacy `recorded_by` shadow
/// column. The PK is `(workspace_id, event_id)` (already migrated in
/// Stage 2); step 5C finishes the migration by removing the unused
/// shadow column and its index.
///
/// This is the row that powers the cross-tenant key replay path: a new
/// joiner reads `WHERE workspace_id = ?` regardless of which existing
/// tenant first projected the share, so the `key_shared` history is
/// naturally global per-workspace.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "key_shared")? {
        Some(cols) => {
            cols != vec!["workspace_id".to_string(), "event_id".to_string()]
                || has_recorded_by(conn, "key_shared")?
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS key_shared")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_shared (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            frontier_count INTEGER NOT NULL,
            frontier_ref_1 TEXT NOT NULL,
            frontier_ref_2 TEXT NOT NULL,
            frontier_ref_3 TEXT NOT NULL,
            frontier_ref_4 TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            delivery_target_id TEXT NOT NULL,
            recipient_event_id TEXT NOT NULL,
            wrapped_key BLOB NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_key_shared_event_id
            ON key_shared(event_id);
        CREATE INDEX IF NOT EXISTS idx_key_shared_key_event_id
            ON key_shared(workspace_id, key_event_id);
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

/// Pure projector: KeyShared -> key_shared table.
///
/// Plan.md "no scaffolding" rule (Forking plan): the projector reads only
/// `{event, deps, labels}`. Validation rules:
///
/// - Apply the standard label-gate: any `removed_by:*` / `superseded` /
///   `deleted` label on this event id rejects the projection.
/// - The carried `frontier_hash` must equal `frontier_hash_from_refs` of
///   the declared frontier refs (canonically sorted, in-bounds).
/// - The carried `delivery_target_id` must be the deterministic
///   `delivery_target_id(key_event_id, frontier_hash, recipient_event_id,
///   unwrap_key_event_id)`.
///
/// Note: the legacy "DH-unwrap key material from invite_secrets" step
/// (which used `ctx.unwrapped_secret_material` to emit a deterministic
/// KeySecret blob) has been removed. That side effect was driven by the
/// old authoring-side codepath, not by deterministic projection.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ss = match parsed {
        ParsedEvent::KeyShared(s) => s,
        _ => return ProjectorResult::reject("not a key_shared event".to_string()),
    };

    // Generic label-gate (plan.md §164-170).
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "key_shared gated by label `{}`",
                    t
                ));
            }
        }
    }

    // Plan.md Stage 3.5 step 5C: `recorded_by` shadow column dropped.
    // The projector no longer reads or writes it.
    let slots = [
        ss.frontier_ref_1,
        ss.frontier_ref_2,
        ss.frontier_ref_3,
        ss.frontier_ref_4,
    ];
    let refs = match frontier_refs_from_slots(ss.frontier_count, &slots) {
        Ok(refs) => refs,
        Err(reason) => return ProjectorResult::reject(reason),
    };
    if let Err(reason) = validate_canonical_frontier_refs(&refs) {
        return ProjectorResult::reject(reason);
    }
    let expected_frontier_hash = frontier_hash_from_refs(&refs);
    if ss.frontier_hash != expected_frontier_hash {
        return ProjectorResult::reject(
            "frontier_hash does not match key_shared frontier".to_string(),
        );
    }

    let expected_delivery_target_id = delivery_target_id(
        &ss.key_event_id,
        &ss.frontier_hash,
        &ss.recipient_event_id,
        &ss.unwrap_key_event_id,
    );
    if ss.delivery_target_id != expected_delivery_target_id {
        return ProjectorResult::reject(
            "delivery_target_id does not match key_shared target".to_string(),
        );
    }

    let workspace_id_b64 = event_id_to_base64(&ss.workspace_id);
    let key_b64 = event_id_to_base64(&ss.key_event_id);
    let frontier_b64 = event_id_to_base64(&ss.frontier_hash);
    let delivery_target_b64 = event_id_to_base64(&ss.delivery_target_id);
    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "key_shared",
        columns: vec![
            "workspace_id",
            "event_id",
            "key_event_id",
            "frontier_count",
            "frontier_ref_1",
            "frontier_ref_2",
            "frontier_ref_3",
            "frontier_ref_4",
            "frontier_hash",
            "delivery_target_id",
            "recipient_event_id",
            "wrapped_key",
        ],
        values: vec![
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(key_b64),
            SqlVal::Int(ss.frontier_count as i64),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_1)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_2)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_3)),
            SqlVal::Text(event_id_to_base64(&ss.frontier_ref_4)),
            SqlVal::Text(frontier_b64),
            SqlVal::Text(delivery_target_b64),
            SqlVal::Text(recipient_b64),
            SqlVal::Blob(ss.wrapped_key.to_vec()),
        ],
    }];

    // Plan.md "no scaffolding": the legacy DH-unwrap-then-emit-secret
    // step is gone. It was driven by `ctx.unwrapped_secret_material` —
    // a bespoke field populated by the old authoring-side codepath.
    // The pure projector cannot perform DH on its own; if a future
    // deterministic supplement is wanted (e.g. a KeySecret event that
    // rides on a declared dep), it must arrive through the standard
    // `{event, deps, labels}` channel.
    ProjectorResult::valid(ops)
}

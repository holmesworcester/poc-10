use super::super::ParsedEvent;
use super::codec::{
    frontier_hash_from_refs, frontier_refs_from_slots, validate_canonical_frontier_refs,
};
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// `removals` projection table.
///
/// Plan.md round-9 step 1 — primary key migration:
/// `(recorded_by, event_id)` → `(workspace_id, event_id)`. The new key
/// reflects the post-`recorded_by` model: a removal is uniquely
/// identified by the workspace it scopes to and the event id of the
/// removal itself, not per-tenant duplicated. There is no `recorded_by`
/// shadow column on this table — round-9 step 1 drops it outright.
///
/// Per-tenant queries against `removals` resolve the caller's
/// workspace_id from `invites_accepted` (the same shape every other
/// post-Stage-2 table uses) and filter on `WHERE workspace_id = ?1`.
///
/// For poc-8 dev we DROP+CREATE on schema-init when the existing PK
/// shape doesn't match the new key.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "removals")? {
        Some(cols) => cols != vec!["workspace_id".to_string(), "event_id".to_string()],
        None => false, // table doesn't exist yet — create fresh below
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS removals")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS removals (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            removed_member_ref TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            parent_count INTEGER NOT NULL,
            parent_1 TEXT NOT NULL,
            parent_2 TEXT NOT NULL,
            parent_3 TEXT NOT NULL,
            parent_4 TEXT NOT NULL,
            remover_signer_event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_removals_event_id
            ON removals(event_id);
        ",
    )?;
    Ok(())
}

/// Read the PRIMARY KEY column names for `table`, in PK ordinal order.
/// Returns `None` if the table does not exist.
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
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let removal = match parsed {
        ParsedEvent::Removal(event) => event,
        _ => return ProjectorResult::reject("not a removal event".to_string()),
    };
    if removal.removed_by != removal.signed_by {
        return ProjectorResult::reject("removed_by must equal signed_by".to_string());
    }
    let slots = [
        removal.parent_1,
        removal.parent_2,
        removal.parent_3,
        removal.parent_4,
    ];
    let refs = match frontier_refs_from_slots(removal.parent_count, &slots) {
        Ok(refs) => refs,
        Err(reason) => return ProjectorResult::reject(reason),
    };
    if let Err(reason) = validate_canonical_frontier_refs(&refs) {
        return ProjectorResult::reject(reason);
    }
    let expected_hash = frontier_hash_from_refs(&refs);
    if expected_hash != removal.frontier_hash {
        return ProjectorResult::reject("frontier_hash does not match parent frontier".to_string());
    }

    // Plan.md (Forking plan, "no scaffolding"): workspace_id is now a
    // real wire field on `RemovalEvent`. The projector reads it directly
    // — no fallback to bespoke `ctx.accepted_workspace_id` (the new chain
    // doesn't populate that field).
    let workspace_id_b64 = event_id_to_base64(&removal.workspace_id);
    let workspace_id_bytes = removal.workspace_id.to_vec();

    // Label key per plan.md §164-170: `removed_by:<issuer-event-id>`. Future
    // content events whose signer/author resolves to `removed_member_ref`
    // pick up the label via `ctx.labels` and refuse to project.
    let removed_by_b64 = event_id_to_base64(&removal.removed_by);
    let label_type = format!("removed_by:{}", removed_by_b64);

    ProjectorResult::valid(vec![
        WriteOp::InsertOrIgnore {
            table: "removals",
            columns: vec![
                "workspace_id",
                "event_id",
                "removed_member_ref",
                "frontier_hash",
                "parent_count",
                "parent_1",
                "parent_2",
                "parent_3",
                "parent_4",
                "remover_signer_event_id",
            ],
            values: vec![
                SqlVal::Text(workspace_id_b64),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(event_id_to_base64(&removal.removed_member_ref)),
                SqlVal::Text(event_id_to_base64(&removal.frontier_hash)),
                SqlVal::Int(removal.parent_count as i64),
                SqlVal::Text(event_id_to_base64(&removal.parent_1)),
                SqlVal::Text(event_id_to_base64(&removal.parent_2)),
                SqlVal::Text(event_id_to_base64(&removal.parent_3)),
                SqlVal::Text(event_id_to_base64(&removal.parent_4)),
                SqlVal::Text(event_id_to_base64(&removal.signed_by)),
            ],
        },
        // Reified gate: `removed_by:<issuer>` keyed on the removed identity.
        WriteOp::InsertOrIgnore {
            table: "labels",
            columns: vec!["event_id", "label_type", "workspace_id"],
            values: vec![
                SqlVal::Blob(removal.removed_member_ref.to_vec()),
                SqlVal::Text(label_type),
                SqlVal::Blob(workspace_id_bytes),
            ],
        },
    ])
}

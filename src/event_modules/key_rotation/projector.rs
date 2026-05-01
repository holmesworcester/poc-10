use super::super::removal::{
    frontier_hash_from_refs, frontier_refs_from_slots, validate_canonical_frontier_refs,
};
use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// `key_rotations` projection table.
///
/// Plan.md round-9 step 2 — drop the legacy `recorded_by` shadow column.
/// The PK is `(workspace_id, event_id)` (already migrated in Stage 2);
/// step 2 finishes the migration by removing the unused shadow column
/// and its index. Per-tenant queries against `key_rotations` resolve the
/// caller's workspace_id from `invites_accepted` and filter on
/// `WHERE workspace_id = ?1`.
///
/// For poc-8 dev we DROP+CREATE on schema-init when the existing table
/// still carries the legacy `recorded_by` column.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match table_state(conn, "key_rotations")? {
        Some(state) => {
            state.pk != vec!["workspace_id".to_string(), "event_id".to_string()]
                || state.has_recorded_by
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS key_rotations")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS key_rotations (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            key_event_id TEXT NOT NULL,
            frontier_hash TEXT NOT NULL,
            frontier_count INTEGER NOT NULL,
            frontier_ref_1 TEXT NOT NULL,
            frontier_ref_2 TEXT NOT NULL,
            frontier_ref_3 TEXT NOT NULL,
            frontier_ref_4 TEXT NOT NULL,
            rotator_signer_event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_key_rotations_event_id
            ON key_rotations(event_id);
        CREATE INDEX IF NOT EXISTS idx_key_rotations_key_event_id
            ON key_rotations(workspace_id, key_event_id);
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

pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let rotation = match parsed {
        ParsedEvent::KeyRotation(event) => event,
        _ => return ProjectorResult::reject("not a key_rotation event".to_string()),
    };

    // Generic label-gate (plan.md §164-170).
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "key_rotation gated by label `{}`",
                    t
                ));
            }
        }
    }

    // Plan.md round-9 step 2: `recorded_by` shadow column dropped.
    // The projector no longer reads or writes it.
    if rotation.rotated_by != rotation.signed_by {
        return ProjectorResult::reject("rotated_by must equal signed_by".to_string());
    }
    let slots = [
        rotation.frontier_ref_1,
        rotation.frontier_ref_2,
        rotation.frontier_ref_3,
        rotation.frontier_ref_4,
    ];
    let refs = match frontier_refs_from_slots(rotation.frontier_count, &slots) {
        Ok(refs) => refs,
        Err(reason) => return ProjectorResult::reject(reason),
    };
    if let Err(reason) = validate_canonical_frontier_refs(&refs) {
        return ProjectorResult::reject(reason);
    }
    let expected_hash = frontier_hash_from_refs(&refs);
    if expected_hash != rotation.frontier_hash {
        return ProjectorResult::reject("frontier_hash does not match frontier refs".to_string());
    }

    let workspace_id_b64 = event_id_to_base64(&rotation.workspace_id);

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "key_rotations",
        columns: vec![
            "workspace_id",
            "event_id",
            "key_event_id",
            "frontier_hash",
            "frontier_count",
            "frontier_ref_1",
            "frontier_ref_2",
            "frontier_ref_3",
            "frontier_ref_4",
            "rotator_signer_event_id",
        ],
        values: vec![
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_to_base64(&rotation.key_event_id)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_hash)),
            SqlVal::Int(rotation.frontier_count as i64),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_1)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_2)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_3)),
            SqlVal::Text(event_id_to_base64(&rotation.frontier_ref_4)),
            SqlVal::Text(event_id_to_base64(&rotation.signed_by)),
        ],
    }])
}

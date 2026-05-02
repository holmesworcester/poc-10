pub mod projector;
pub mod queries;
pub mod codec;

// Re-export stable public API so callers import from `event_modules::reaction`.
pub use projector::project_pure;
pub use queries::{
    count, list, list_for_message, list_for_message_with_authors, list_rows, ReactionItem,
    ReactionRow, ReactionWithAuthor,
};
pub use codec::{
    encode_reaction, parse_reaction, ReactionEvent, REACTION_FIELDS, REACTION_TYPE_META,
    REACTION_WIRE_SIZE,
};

use rusqlite::Connection;

/// `reactions` projection table.
///
/// Plan.md round-9 step 5A — drop the legacy `recorded_by` shadow column.
/// The PK is `(workspace_id, event_id)` (already migrated in Stage 2);
/// step 5A finishes the migration by removing the unused shadow column
/// and its index. Per-tenant queries against `reactions` resolve the
/// caller's workspace_id from `invites_accepted` and filter on
/// `WHERE workspace_id = ?1`.
///
/// For poc-8/9 dev we DROP+CREATE on schema-init when the existing PK shape
/// doesn't match or the table still carries the legacy `recorded_by` column.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match table_state(conn, "reactions")? {
        Some(state) => {
            state.pk != vec!["workspace_id".to_string(), "event_id".to_string()]
                || state.has_recorded_by
        }
        None => false, // table doesn't exist yet — create fresh below
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS reactions")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS reactions (
            event_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            target_event_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            emoji TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_reactions_target_ws
            ON reactions(workspace_id, target_event_id);
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

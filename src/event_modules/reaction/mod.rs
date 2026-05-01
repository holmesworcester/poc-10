pub mod commands;
pub mod projector;
pub mod queries;
pub mod codec;

// Re-export stable public API so callers import from `event_modules::reaction`.
pub use commands::{create, react, react_for_peer, CreateReactionCmd, ReactResponse};
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
/// Plan.md Stage 2 — primary key migration: `(recorded_by, event_id)` →
/// `(workspace_id, event_id)`. `recorded_by` remains as a nullable
/// shadow column so the legacy CLI-bridge writers continue to populate
/// it without schema-level errors. Stage 3 drops the column outright.
///
/// Schema migration follows the workspace pattern: when an existing
/// table has the legacy PK shape we DROP+CREATE on schema-init. This is
/// a no-loss reset for fresh in-memory test DBs and for daemon DBs
/// where `reactions` is empty (no reaction has applied through this
/// database yet). Daemons with populated `reactions` rows are still on
/// the legacy chain — the bridge writes the same row under the
/// thread-local `recorded_by`, and `INSERT OR IGNORE` against the new
/// key is a no-op for already-present `(workspace_id, event_id)` pairs.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "reactions")? {
        Some(cols) => cols != vec!["workspace_id".to_string(), "event_id".to_string()],
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
            recorded_by TEXT,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_reactions_target
            ON reactions(recorded_by, target_event_id);
        CREATE INDEX IF NOT EXISTS idx_reactions_target_ws
            ON reactions(workspace_id, target_event_id);
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

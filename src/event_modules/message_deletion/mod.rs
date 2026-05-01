pub mod commands;
pub mod projector;
pub mod queries;
pub mod codec;

// Re-export stable public API so callers import from `event_modules::message_deletion`.
pub use commands::{create, delete_message, CreateMessageDeletionCmd};
pub use projector::project_pure;
pub use queries::list_deleted_ids;
pub use codec::{
    encode_message_deletion, parse_message_deletion, MessageDeletionEvent, MESSAGE_DELETION_META,
    MESSAGE_DELETION_WIRE_SIZE,
};

use rusqlite::Connection;

/// `deleted_messages` projection table.
///
/// Plan.md Stage 2 — primary key migration: `(recorded_by, message_id)`
/// → `(workspace_id, event_id)`. Note: the workspace pattern uses
/// `event_id` as the second key column (the `message_id` column here is
/// the targeted message's event id and acts as that key). `recorded_by`
/// remains as a nullable shadow column so the legacy CLI-bridge writers
/// continue to populate it without schema-level errors. Stage 3 drops
/// the column outright.
///
/// Schema migration follows the workspace pattern: when an existing
/// table has the legacy PK shape we DROP+CREATE on schema-init.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "deleted_messages")? {
        Some(cols) => cols != vec!["workspace_id".to_string(), "message_id".to_string()],
        None => false, // table doesn't exist yet — create fresh below
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS deleted_messages")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS deleted_messages (
            recorded_by TEXT,
            workspace_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            deletion_event_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            deleted_at INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, message_id)
        );
        CREATE INDEX IF NOT EXISTS idx_deleted_messages_recorded
            ON deleted_messages(recorded_by, message_id);

        CREATE TABLE IF NOT EXISTS deletion_intents (
            recorded_by TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            target_id TEXT NOT NULL,
            deletion_event_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, target_kind, target_id, deletion_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_deletion_intents_target
            ON deletion_intents(recorded_by, target_id);
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

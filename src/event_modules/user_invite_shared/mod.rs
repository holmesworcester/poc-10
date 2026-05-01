pub mod projector;
pub mod codec;

pub use projector::project_pure;
pub use codec::{
    encode_user_invite, parse_user_invite, UserInviteEvent, USER_INVITE_META, USER_INVITE_WIRE_SIZE,
};

use rusqlite::Connection;

/// `user_invites` projection table.
///
/// Plan.md Stage 3.5 step 5B — drop the legacy `recorded_by` shadow
/// column. The PK is `(workspace_id, event_id)` (already migrated in
/// Stage 2); step 5B finishes the migration by removing the unused
/// shadow column and its index. Per-tenant queries against
/// `user_invites` resolve the caller's workspace_id from the
/// caller-side workspace binding and filter on `WHERE workspace_id = ?1`.
///
/// For poc-8 dev we DROP+CREATE on schema-init when the existing table
/// still carries the legacy `recorded_by` column or the wrong PK shape.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match table_state(conn, "user_invites")? {
        Some(state) => {
            state.pk != vec!["workspace_id".to_string(), "event_id".to_string()]
                || state.has_recorded_by
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS user_invites")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS user_invites (
            workspace_id TEXT,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_user_invites_event_id
            ON user_invites(event_id);
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

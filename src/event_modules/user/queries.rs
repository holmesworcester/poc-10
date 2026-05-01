use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserItem {
    pub event_id: String,
    pub username: String,
}

/// List user items (response type) from the database.
pub fn list_items(db: &Connection, recorded_by: &str) -> Result<Vec<UserItem>, rusqlite::Error> {
    let rows = list(db, recorded_by)?;
    Ok(rows
        .into_iter()
        .map(|row| UserItem {
            event_id: row.event_id,
            username: row.username,
        })
        .collect())
}

pub struct UserRow {
    pub event_id: String,
    pub username: String,
}

/// List users for a given tenant.
///
/// Plan.md Stage 2: `users` is now keyed by `(workspace_id, event_id)` — it
/// is global, not per-tenant. To preserve the legacy per-tenant `list`
/// semantics we restrict via `invites_accepted` (still keyed on
/// `recorded_by`). This mirrors the pattern used by workspace::list.
pub fn list(db: &Connection, recorded_by: &str) -> Result<Vec<UserRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT u.event_id, COALESCE(u.username, '')
         FROM users u
         WHERE EXISTS (
             SELECT 1 FROM invites_accepted ia
             WHERE ia.recorded_by = ?1
               AND ia.workspace_id = u.workspace_id
         )",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(UserRow {
                event_id: row.get(0)?,
                username: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn count(db: &Connection, recorded_by: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM users u
         WHERE EXISTS (
             SELECT 1 FROM invites_accepted ia
             WHERE ia.recorded_by = ?1
               AND ia.workspace_id = u.workspace_id
         )",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

/// Return the first user event_id, if any.
pub fn first_event_id(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT u.event_id FROM users u
         WHERE EXISTS (
             SELECT 1 FROM invites_accepted ia
             WHERE ia.recorded_by = ?1
               AND ia.workspace_id = u.workspace_id
         )
         LIMIT 1",
        rusqlite::params![recorded_by],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

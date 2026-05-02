use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserItem {
    pub event_id: String,
    pub username: String,
}

/// List user items (response type) from the database.
pub fn list_items(db: &Connection, workspace_id: &str) -> Result<Vec<UserItem>, rusqlite::Error> {
    let rows = list(db, workspace_id)?;
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

/// List users for a workspace.
pub fn list(db: &Connection, workspace_id: &str) -> Result<Vec<UserRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT event_id, COALESCE(username, '')
         FROM users
         WHERE workspace_id = ?1",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            Ok(UserRow {
                event_id: row.get(0)?,
                username: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn count(db: &Connection, workspace_id: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM users WHERE workspace_id = ?1",
        rusqlite::params![workspace_id],
        |row| row.get(0),
    )
}

/// Return the first user event_id, if any.
pub fn first_event_id(
    db: &Connection,
    workspace_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT event_id FROM users WHERE workspace_id = ?1 LIMIT 1",
        rusqlite::params![workspace_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

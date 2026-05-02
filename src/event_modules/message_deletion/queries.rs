use rusqlite::Connection;

/// List deleted-message ids for a workspace.
pub fn list_deleted_ids(
    db: &Connection,
    workspace_id: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT message_id FROM deleted_messages WHERE workspace_id = ?1",
    )?;
    let ids = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids)
}

pub fn count(db: &Connection, workspace_id: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM deleted_messages WHERE workspace_id = ?1",
        rusqlite::params![workspace_id],
        |row| row.get(0),
    )
}

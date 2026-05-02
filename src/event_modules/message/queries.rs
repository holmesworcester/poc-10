use crate::crypto::{self, b64_to_hex, event_id_from_base64, EventId};
use crate::event_modules::reaction;
use rusqlite::Connection;

pub struct MessageRow {
    pub message_id_b64: String,
    pub message_id_hex: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
}

/// List messages for a single workspace (base64 workspace_id).
pub fn list_rows(
    db: &Connection,
    workspace_id: &str,
    limit: usize,
) -> Result<Vec<MessageRow>, rusqlite::Error> {
    let query = if limit > 0 {
        format!(
            "SELECT * FROM (
                SELECT m.message_id, m.author_id, m.content, m.created_at,
                       COALESCE(u.username, '') as author_name
                FROM messages m
                LEFT JOIN users u ON m.author_id = u.event_id
                WHERE m.workspace_id = ?1
                ORDER BY m.created_at DESC, m.message_id DESC
                LIMIT {}
            ) ORDER BY created_at ASC, message_id ASC",
            limit
        )
    } else {
        "SELECT m.message_id, m.author_id, m.content, m.created_at,
                COALESCE(u.username, '') as author_name
         FROM messages m
         LEFT JOIN users u ON m.author_id = u.event_id
         WHERE m.workspace_id = ?1
         ORDER BY m.created_at ASC, m.message_id ASC"
            .to_string()
    };

    let mut stmt = db.prepare(&query)?;
    let rows = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            let msg_id_b64: String = row.get(0)?;
            let msg_id_hex = b64_to_hex(&msg_id_b64);
            Ok(MessageRow {
                message_id_b64: msg_id_b64,
                message_id_hex: msg_id_hex,
                author_id: row.get(1)?,
                content: row.get(2)?,
                created_at: row.get(3)?,
                author_name: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn count(db: &Connection, workspace_id: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM messages WHERE workspace_id = ?1",
        rusqlite::params![workspace_id],
        |row| row.get(0),
    )
}

pub fn resolve_number(
    db: &Connection,
    workspace_id: &str,
    num: usize,
) -> Result<EventId, String> {
    if num == 0 {
        return Err("message number must be >= 1".into());
    }
    let mut stmt = db
        .prepare(
            "SELECT message_id FROM messages
             WHERE workspace_id = ?1
             ORDER BY created_at ASC, rowid ASC
             LIMIT 1 OFFSET ?2",
        )
        .map_err(|e| e.to_string())?;
    let msg_id_b64: Option<String> = stmt
        .query_row(rusqlite::params![workspace_id, num - 1], |row| row.get(0))
        .ok();
    match msg_id_b64 {
        Some(b64) => event_id_from_base64(&b64)
            .ok_or_else(|| format!("invalid event ID for message {}", num)),
        None => {
            let total = count(db, workspace_id).map_err(|e| e.to_string())?;
            Err(format!(
                "invalid message number {}; available: 1-{}",
                num, total
            ))
        }
    }
}

pub fn resolve(db: &Connection, workspace_id: &str, selector: &str) -> Result<EventId, String> {
    let stripped = selector.strip_prefix('#').unwrap_or(selector);
    if let Ok(num) = stripped.parse::<usize>() {
        resolve_number(db, workspace_id, num)
    } else {
        crypto::event_id_from_hex(selector)
            .ok_or_else(|| format!("invalid hex event ID: {}", selector))
    }
}

/// Assemble a MessagesResponse from the database.
pub fn list(
    db: &Connection,
    workspace_id: &str,
    limit: usize,
) -> Result<super::MessagesResponse, rusqlite::Error> {
    let rows = list_rows(db, workspace_id, limit)?;
    let total = count(db, workspace_id)?;

    // Load client_op_id mappings for annotation. local_client_ops is keyed by
    // peer_id (an artifact of the legacy CLI write path); we look these up
    // by the workspace's primary peer where available, falling back to empty.
    let client_ops = crate::db::local_client_ops::all_mappings(db, workspace_id).unwrap_or_default();

    let mut messages = Vec::with_capacity(rows.len());
    for row in rows {
        let reactions: Vec<super::ReactionSummary> =
            reaction::list_for_message_with_authors(db, workspace_id, &row.message_id_b64)?
                .into_iter()
                .map(|r| super::ReactionSummary {
                    emoji: r.emoji,
                    reactor_name: r.reactor_name,
                })
                .collect();

        let client_op_id = client_ops.get(&row.message_id_b64).cloned();

        messages.push(super::MessageItem {
            id: row.message_id_hex,
            id_b64: row.message_id_b64,
            author_id: row.author_id,
            author_name: row.author_name,
            content: row.content,
            created_at: row.created_at,
            reactions,
            client_op_id,
        });
    }

    Ok(super::MessagesResponse { messages, total })
}

// ---------------------------------------------------------------------------
// Message deletion queries (moved from message_deletion/queries.rs)
// ---------------------------------------------------------------------------

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

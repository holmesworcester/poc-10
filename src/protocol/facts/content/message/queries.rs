//! Read-only queries over semantic message projections.
//!
//! Message projection splits the durable view into live opened messages,
//! authored message rows, and tombstones. This file gathers those rows for UI,
//! CLI, retention, and sync helpers without changing state. Keep it as the
//! place to ask "what messages does the store currently expose?" rather than
//! "should this message be admitted?"

use crate::core::facts::FactId;
use crate::core::store::Store;
use rusqlite::{params, OptionalExtension};

use super::rows;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMessage {
    pub message_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: FactId,
    pub signer_id: FactId,
    pub text: String,
}

pub fn opened_messages(store: &Store, workspace_id: FactId) -> Result<Vec<OpenedMessage>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT message_id, created_at_ms, author_user_id, signer_id, text
             FROM opened_message_rows
             WHERE workspace_id = ?1
             ORDER BY created_at_ms, message_id",
        )
        .map_err(|err| format!("read opened message rows: {err}"))?;
    let rows = stmt
        .query_map(params![workspace_id], |row| {
            let text = String::from_utf8(row.get::<_, Vec<u8>>(4)?)
                .map_err(|err| rusqlite::Error::InvalidParameterName(err.to_string()))?;
            Ok(OpenedMessage {
                message_id: row.get(0)?,
                created_at_ms: row.get::<_, i64>(1)? as u64,
                author_user_id: row.get(2)?,
                signer_id: row.get(3)?,
                text,
            })
        })
        .map_err(|err| format!("read opened message rows: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("decode opened message rows: {err}"))?;
    Ok(rows)
}

pub(crate) fn max_created_at_ms(store: &Store) -> Result<u64, String> {
    store
        .conn()
        .query_row(
            "SELECT COALESCE(MAX(created_at_ms), 0) FROM content_messages",
            [],
            |row| row.get::<_, i64>(0).map(|value| value as u64),
        )
        .map_err(|err| format!("load content messages for clock: {err}"))
}

pub fn content_message_rows(
    store: &Store,
    workspace_id: FactId,
) -> Result<Vec<rows::ContentMessageRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT message_id, author_user_id, created_at_ms, signer_id, frontier_id, minute, leaf_id
             FROM content_messages
             WHERE workspace_id = ?1 AND deleted = 0
             ORDER BY created_at_ms, message_id",
        )
        .map_err(|err| format!("load message rows: {err}"))?;
    let rows = stmt
        .query_map(params![workspace_id], |row| {
            Ok(rows::ContentMessageRow {
                workspace_id,
                message_id: row.get(0)?,
                author_user_id: row.get(1)?,
                created_at_ms: row.get::<_, i64>(2)? as u64,
                signer_id: row.get(3)?,
                frontier_id: row.get(4)?,
                minute: row.get::<_, i64>(5)? as u64,
                leaf_id: row.get(6)?,
            })
        })
        .map_err(|err| format!("load message rows: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("decode message rows: {err}"))?;
    Ok(rows)
}

pub(crate) fn message_author_user_id(
    store: &Store,
    workspace_id: FactId,
    message_id: FactId,
) -> Result<Option<FactId>, String> {
    store
        .conn()
        .query_row(
            "SELECT author_user_id
             FROM opened_message_rows
             WHERE workspace_id = ?1 AND message_id = ?2
             UNION ALL
             SELECT author_user_id
             FROM content_messages
             WHERE workspace_id = ?1 AND message_id = ?2 AND deleted = 0
             LIMIT 1",
            params![workspace_id, message_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| format!("read message author: {err}"))
}

pub(crate) fn message_exists(
    store: &Store,
    workspace_id: FactId,
    message_id: FactId,
) -> Result<bool, String> {
    Ok(message_author_user_id(store, workspace_id, message_id)?.is_some())
}

pub(crate) fn retained_floor_from_tombstones(
    store: &Store,
    workspace_id: FactId,
) -> Result<u64, String> {
    store
        .conn()
        .query_row(
            "SELECT COALESCE(MAX(authored_minute), -1)
             FROM message_tombstone_rows
             WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| if value < 0 { 0 } else { value as u64 + 1 })
        .map_err(|err| format!("load message tombstones for send: {err}"))
}

pub(crate) fn message_tombstone_count(
    store: &Store,
    workspace_id: FactId,
) -> Result<usize, String> {
    message_tombstone_count_at_or_after(store, workspace_id, 0)
}

pub(crate) fn message_tombstone_count_at_or_after(
    store: &Store,
    workspace_id: FactId,
    floor_minute: u64,
) -> Result<usize, String> {
    store
        .conn()
        .query_row(
            "SELECT COUNT(*)
             FROM message_tombstone_rows
             WHERE workspace_id = ?1 AND authored_minute >= ?2",
            params![workspace_id, floor_minute as i64],
            |row| row.get::<_, i64>(0).map(|value| value as usize),
        )
        .map_err(|err| format!("load message tombstones: {err}"))
}

pub(crate) fn message_tombstone_ids_below(
    store: &Store,
    workspace_id: FactId,
    floor_minute: u64,
) -> Result<Vec<FactId>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT message_id
             FROM message_tombstone_rows
             WHERE workspace_id = ?1 AND authored_minute < ?2",
        )
        .map_err(|err| format!("read message tombstone rows: {err}"))?;
    let rows = stmt
        .query_map(params![workspace_id, floor_minute as i64], |row| row.get(0))
        .map_err(|err| format!("read message tombstone rows: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("decode message tombstone rows: {err}"))?;
    Ok(rows)
}

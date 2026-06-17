//! Read-only queries over projected workspace users.
//!
//! User rows are admitted only after auth projection validates the
//! surrounding invite or authority chain. These helpers return the current
//! visible membership in deterministic display order for CLI and command code.
//! They should not infer authority from raw facts.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::db::{Db, DEFAULT_QUERY_LIMIT};
use crate::core::facts::FactId;
use crate::core::wire::FixedText;
use rusqlite::{params, OptionalExtension, Row};

use super::fact::{UserId, Username, WorkspaceId, USERNAME_BYTES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub user_invite_id: [u8; 32],
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

pub fn decode_user_row(row: &Row<'_>) -> rusqlite::Result<UserRow> {
    let bytes: Vec<u8> = row.get(5)?;
    let padded: [u8; USERNAME_BYTES] = bytes.as_slice().try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName("username slot has wrong length".to_string())
    })?;
    let username: Username = FixedText::from_padded(padded)
        .map_err(|err| rusqlite::Error::InvalidParameterName(format!("{err:?}")))?;
    Ok(UserRow {
        workspace_id: row.get(0)?,
        user_id: row.get(1)?,
        created_at_ms: row.get::<_, i64>(2)? as u64,
        public_key: row.get(3)?,
        user_invite_id: row.get(4)?,
        username: username.to_string(),
    })
}

pub fn users_in_workspace(store: &Db, workspace_id: FactId) -> Result<Vec<UserRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id,
                    user_id,
                    created_at_ms,
                    public_key,
                    user_invite_id,
                    username
             FROM user_rows
             WHERE workspace_id = ?1
             ORDER BY username, user_id
             LIMIT ?2",
        )
        .map_err(|err| format!("load users: {err}"))?;
    let rows = stmt
        .query_map(
            params![workspace_id, DEFAULT_QUERY_LIMIT as i64],
            decode_user_row,
        )
        .map_err(|err| format!("load users: {err}"))?;
    let mut rows = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode users: {err}"))?;
    rows.sort_by(|left, right| {
        left.username
            .cmp(&right.username)
            .then_with(|| left.user_id.cmp(&right.user_id))
    });
    Ok(rows)
}

pub fn user_by_id(
    store: &Db,
    workspace_id: FactId,
    user_id: FactId,
) -> Result<Option<UserRow>, String> {
    store
        .conn()
        .query_row(
            "SELECT workspace_id,
                    user_id,
                    created_at_ms,
                    public_key,
                    user_invite_id,
                    username
             FROM user_rows
             WHERE workspace_id = ?1 AND user_id = ?2
             LIMIT 1",
            params![workspace_id, user_id],
            decode_user_row,
        )
        .optional()
        .map_err(|err| format!("load user row: {err}"))
}

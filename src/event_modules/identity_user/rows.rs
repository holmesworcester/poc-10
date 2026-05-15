//! Projection row layouts for user state.
//!
//! Rows are keyed by `workspace_id || user_id`. The user id is the fact id of
//! the user fact being projected.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::store::{TableName, TableRow};

use super::fact::{UserFact, UserId, WorkspaceId};
use super::layout;

pub const USER_ROWS: TableName = TableName::new("user_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub user_invite_id: [u8; 32],
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

pub fn user_key(workspace_id: &WorkspaceId, user_id: &UserId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(user_id);
    key
}

pub fn user_row(
    user_id: UserId,
    user_invite_id: [u8; 32],
    fact: &UserFact,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: USER_ROWS,
        key: user_key(&fact.workspace_id, &user_id),
        value: layout::encode_row_value(&user_invite_id, fact)?,
    })
}

pub fn decode_user_row(key: &[u8], value: &[u8]) -> Result<UserRow, String> {
    if key.len() != 64 {
        return Err("user row key must be workspace_id || user_id".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut user_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    user_id.copy_from_slice(&key[32..]);
    let decoded = layout::decode_row_value(value)?;
    Ok(UserRow {
        workspace_id,
        user_id,
        user_invite_id: decoded.user_invite_id,
        created_at_ms: decoded.created_at_ms,
        public_key: decoded.public_key,
        username: decoded.username,
    })
}

//! Projection row layouts for user-invite state.
//!
//! Rows are keyed by `workspace_id || user_invite_id`. The user-invite id is
//! the fact id of the user-invite fact being projected.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{UserInviteFact, WorkspaceId};
use super::layout;

pub const USER_INVITE_ROWS: TableName = TableName::new("user_invite_rows");

pub type UserInviteId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInviteRow {
    pub workspace_id: WorkspaceId,
    pub user_invite_id: UserInviteId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub authority_event_id: FactId,
}

pub fn user_invite_key(workspace_id: &WorkspaceId, user_invite_id: &UserInviteId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(user_invite_id);
    key
}

pub fn user_invite_row(
    user_invite_id: UserInviteId,
    fact: &UserInviteFact,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: USER_INVITE_ROWS,
        key: user_invite_key(&fact.workspace_id, &user_invite_id),
        value: layout::encode_row_value(fact)?,
    })
}

pub fn decode_user_invite_row(key: &[u8], value: &[u8]) -> Result<UserInviteRow, String> {
    if key.len() != 64 {
        return Err("user_invite row key must be workspace_id || user_invite_id".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut user_invite_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    user_invite_id.copy_from_slice(&key[32..]);
    let decoded = layout::decode_row_value(value)?;
    Ok(UserInviteRow {
        workspace_id,
        user_invite_id,
        created_at_ms: decoded.created_at_ms,
        public_key: decoded.public_key,
        authority_event_id: decoded.authority_event_id,
    })
}

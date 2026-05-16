//! Projection row layouts for invite-server state.
//!
//! Rows are keyed by `workspace_id || invite_server_id`. The invite-server id
//! is the fact id of the invite-server fact being projected.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{InviteServerFact, WorkspaceId};
use super::layout;

pub const INVITE_SERVER_ROWS: TableName = TableName::new("invite_server_rows");

pub type InviteServerId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteServerRow {
    pub workspace_id: WorkspaceId,
    pub invite_server_id: InviteServerId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub authority_event_id: FactId,
}

pub fn invite_server_key(workspace_id: &WorkspaceId, invite_server_id: &InviteServerId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(invite_server_id);
    key
}

pub fn invite_server_row(
    invite_server_id: InviteServerId,
    fact: &InviteServerFact,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: INVITE_SERVER_ROWS,
        key: invite_server_key(&fact.workspace_id, &invite_server_id),
        value: layout::encode_row_value(fact)?,
    })
}

pub fn decode_invite_server_row(key: &[u8], value: &[u8]) -> Result<InviteServerRow, String> {
    if key.len() != 64 {
        return Err("invite_server row key must be workspace_id || invite_server_id".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut invite_server_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    invite_server_id.copy_from_slice(&key[32..]);
    let decoded = layout::decode_row_value(value)?;
    Ok(InviteServerRow {
        workspace_id,
        invite_server_id,
        created_at_ms: decoded.created_at_ms,
        public_key: decoded.public_key,
        authority_event_id: decoded.authority_event_id,
    })
}

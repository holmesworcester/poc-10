//! Projection row layouts for admin grant state.
//!
//! Rows are keyed by `workspace_id || admin_id`, so the same admin fact id in
//! another workspace cannot collide.

use crate::core::store::{TableName, TableRow};

use super::fact::{AdminFact, AdminId, AdminPublicKey, UserId, WorkspaceId};
use super::layout;

pub const ADMIN_ROWS: TableName = TableName::new("admin_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRow {
    pub workspace_id: WorkspaceId,
    pub admin_id: AdminId,
    pub created_at_ms: u64,
    pub public_key: AdminPublicKey,
    pub authority_fact_id: [u8; 32],
    pub user_fact_id: UserId,
}

pub fn admin_key(workspace_id: &WorkspaceId, admin_id: &AdminId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(admin_id);
    key
}

pub fn admin_row(admin_id: AdminId, fact: &AdminFact) -> Result<TableRow, String> {
    Ok(TableRow {
        table: ADMIN_ROWS,
        key: admin_key(&fact.workspace_id, &admin_id),
        value: layout::encode_row_value(fact)?,
    })
}

pub fn decode_admin_row(key: &[u8], value: &[u8]) -> Result<AdminRow, String> {
    if key.len() != 64 {
        return Err("admin row key must be workspace_id || admin_id".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut admin_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    admin_id.copy_from_slice(&key[32..]);
    let decoded = layout::decode_row_value(value)?;
    Ok(AdminRow {
        workspace_id,
        admin_id,
        created_at_ms: decoded.created_at_ms,
        public_key: decoded.public_key,
        authority_fact_id: decoded.authority_fact_id,
        user_fact_id: decoded.user_fact_id,
    })
}

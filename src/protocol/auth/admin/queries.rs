//! Read-only admin grant projection queries.
//!
//! Query helpers are the only admin module functions that inspect projected row
//! state directly. They never write, construct facts, project, or dispatch
//! intents.

use crate::core::db::{Db, DEFAULT_QUERY_LIMIT};
use rusqlite::{params, Row};

use super::fact::{AdminId, AdminPublicKey, UserId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRow {
    pub workspace_id: WorkspaceId,
    pub admin_id: AdminId,
    pub created_at_ms: u64,
    pub public_key: AdminPublicKey,
    pub authority_fact_id: [u8; 32],
    pub user_fact_id: UserId,
}

pub fn admin_rows_in_workspace(
    store: &Db,
    workspace_id: WorkspaceId,
) -> Result<Vec<AdminRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id,
                    admin_id,
                    created_at_ms,
                    public_key,
                    authority_fact_id,
                    user_fact_id
             FROM admin_rows
             WHERE workspace_id = ?1
             ORDER BY admin_id
             LIMIT ?2",
        )
        .map_err(|err| format!("load admin rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![workspace_id, DEFAULT_QUERY_LIMIT as i64],
            decode_admin_row,
        )
        .map_err(|err| format!("load admin rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode admin rows: {err}"))
}

pub fn decode_admin_row(row: &Row<'_>) -> rusqlite::Result<AdminRow> {
    Ok(AdminRow {
        workspace_id: row.get(0)?,
        admin_id: row.get(1)?,
        created_at_ms: row.get::<_, i64>(2)? as u64,
        public_key: row.get(3)?,
        authority_fact_id: row.get(4)?,
        user_fact_id: row.get(5)?,
    })
}

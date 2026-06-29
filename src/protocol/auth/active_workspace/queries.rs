//! Read model for the active-workspace selection.
//!
//! Resolves the most recently selected workspace from the projected rows. Used
//! by the command boundary to default an omitted `WORKSPACE_ID_HEX`.

use crate::core::db::Db;
use crate::core::facts::FactId;
use rusqlite::{OptionalExtension, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveWorkspaceRow {
    pub setting_fact_id: FactId,
    pub effective_at_ms: u64,
    pub workspace_id: FactId,
}

/// The most recently selected active workspace, if any has been set.
pub fn current_active_workspace(store: &Db) -> Result<Option<FactId>, String> {
    store
        .conn()
        .query_row(
            "SELECT setting_fact_id, workspace_id, effective_at_ms
             FROM active_workspace_rows
             ORDER BY effective_at_ms DESC, setting_fact_id DESC
             LIMIT 1",
            [],
            decode_setting_row,
        )
        .optional()
        .map(|row| row.map(|row| row.workspace_id))
        .map_err(|err| format!("read active workspace row: {err}"))
}

fn decode_setting_row(row: &Row<'_>) -> rusqlite::Result<ActiveWorkspaceRow> {
    Ok(ActiveWorkspaceRow {
        setting_fact_id: row.get(0)?,
        workspace_id: row.get(1)?,
        effective_at_ms: row.get::<_, i64>(2)? as u64,
    })
}

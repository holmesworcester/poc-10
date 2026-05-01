//! Read queries for the `files` projection table.
//!
//! Wave 1 trim: only the minimal listing/lookup helpers needed for
//! perf testing + chain integration. The full poc-7 download-rate
//! analytics (sync_runs joins, slices_received progress) are deferred
//! until the file-streaming feature is rewired into the new chain.

use crate::crypto::{b64_to_hex, event_id_to_base64};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileItem {
    pub file_event_id: String,
    pub workspace_id: String,
    pub file_name: String,
    pub size_bytes: i64,
    pub slice_count: i64,
    pub created_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilesResponse {
    pub files: Vec<FileItem>,
    pub total: i64,
}

/// List all files for a workspace (chain-friendly: workspace_id-scoped read).
pub fn list_for_workspace(
    db: &Connection,
    workspace_id: &[u8; 32],
) -> Result<FilesResponse, rusqlite::Error> {
    let workspace_id_b64 = event_id_to_base64(workspace_id);
    let mut stmt = db.prepare(
        "SELECT event_id, file_name, size_bytes, slice_count, created_at_ms
         FROM files
         WHERE workspace_id = ?1
         ORDER BY created_at_ms ASC, event_id ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![&workspace_id_b64], |row| {
            let event_id_b64: String = row.get(0)?;
            Ok(FileItem {
                file_event_id: b64_to_hex(&event_id_b64),
                workspace_id: workspace_id_b64.clone(),
                file_name: row.get(1)?,
                size_bytes: row.get(2)?,
                slice_count: row.get(3)?,
                created_at_ms: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let total: i64 = db.query_row(
        "SELECT COUNT(*) FROM files WHERE workspace_id = ?1",
        rusqlite::params![&workspace_id_b64],
        |row| row.get(0),
    )?;
    Ok(FilesResponse {
        files: rows,
        total,
    })
}

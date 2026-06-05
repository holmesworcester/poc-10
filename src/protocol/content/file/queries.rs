//! Read-only queries over projected file attachments.
//!
//! File facts project into durable rows only after their message context and
//! deletion state have been resolved. This module exposes the resulting live
//! attachment view for CLI selection and display. It should not decide whether
//! a file is valid or deleted; those invariants belong to file projection and
//! file-deletion projection.

use crate::core::facts::FactId;
use crate::core::store::Store;
use rusqlite::params;

use super::fact::{AuthorId, RootHash, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileRow {
    pub workspace_id: WorkspaceId,
    pub file_fact_id: FactId,
    pub created_at_ms: u64,
    pub message_id: FactId,
    pub author_user_id: AuthorId,
    pub file_id: FactId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: RootHash,
    pub sealed_metadata: Vec<u8>,
}

pub fn content_file_rows(
    store: &Store,
    workspace_id: FactId,
) -> Result<Vec<ContentFileRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT file_fact_id, message_id, file_id, author_user_id, created_at_ms,
                    root_hash, byte_len, total_slices, slice_bytes, sealed_metadata
             FROM content_files
             WHERE workspace_id = ?1 AND deleted = 0
             ORDER BY created_at_ms, file_fact_id",
        )
        .map_err(|err| format!("load file rows: {err}"))?;
    let rows = stmt
        .query_map(params![workspace_id], |row| {
            Ok(ContentFileRow {
                workspace_id,
                file_fact_id: row.get(0)?,
                message_id: row.get(1)?,
                file_id: row.get(2)?,
                author_user_id: row.get(3)?,
                created_at_ms: row.get::<_, i64>(4)? as u64,
                root_hash: row.get(5)?,
                blob_bytes: row.get::<_, i64>(6)? as u64,
                total_slices: row.get::<_, i64>(7)? as u32,
                slice_bytes: row.get::<_, i64>(8)? as u32,
                sealed_metadata: row.get(9)?,
            })
        })
        .map_err(|err| format!("load file rows: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("decode file rows: {err}"))?;
    Ok(rows)
}

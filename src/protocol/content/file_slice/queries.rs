//! Read-only queries over content-file-slice projections.
//!
//! Slice rows are keyed by `workspace_id || file_id || slice_index_be` so callers
//! can range-scan a file's slices in order without secondary indices. The value
//! stores the BAO-verified ciphertext alongside the slice's fact id and
//! timestamp. A row means the parent file descriptor's encrypted root hash has
//! already accepted this slice proof. This file gathers those rows without
//! changing state.

use crate::core::db::Db;
use crate::core::facts::FactId;
use rusqlite::params;

use super::fact::WorkspaceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceRow {
    pub workspace_id: WorkspaceId,
    pub file_id: FactId,
    pub slice_index: u32,
    pub slice_fact_id: FactId,
    pub created_at_ms: u64,
    pub ciphertext: Vec<u8>,
}

pub fn file_slice_rows_for_file(
    store: &Db,
    workspace_id: WorkspaceId,
    file_id: FactId,
) -> Result<Vec<ContentFileSliceRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT slice_index, slice_fact_id, created_at_ms, ciphertext
             FROM file_slice_rows
             WHERE workspace_id = ?1 AND file_id = ?2
             ORDER BY slice_index",
        )
        .map_err(|err| format!("load file slices: {err}"))?;
    let rows = stmt
        .query_map(params![workspace_id, file_id], |row| {
            Ok(ContentFileSliceRow {
                workspace_id,
                file_id,
                slice_index: row.get::<_, i64>(0)? as u32,
                slice_fact_id: row.get(1)?,
                created_at_ms: row.get::<_, i64>(2)? as u64,
                ciphertext: row.get(3)?,
            })
        })
        .map_err(|err| format!("load file slices: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("decode file slices: {err}"))?;
    Ok(rows)
}

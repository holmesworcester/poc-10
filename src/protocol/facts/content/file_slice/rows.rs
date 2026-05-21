//! Content-file-slice projection rows.
//!
//! Rows are keyed by `workspace_id || file_id || slice_index_be` so callers can
//! range-scan a file's slices in order without secondary indices. The value
//! stores the opaque ciphertext alongside the slice's fact id and timestamp.

use crate::core::facts::FactId;
use crate::core::store::{Store, TableName, TableRow};
use crate::core::wire;
use rusqlite::params;

use super::fact::{ContentFileSliceFact, WorkspaceId};

pub const FILE_SLICE_ROWS: TableName = TableName::new("file_slice_rows");
pub const ROW_PREFIX_BYTES: usize = 32 + 8 + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceRow {
    pub workspace_id: WorkspaceId,
    pub file_id: FactId,
    pub slice_index: u32,
    pub slice_fact_id: FactId,
    pub created_at_ms: u64,
    pub ciphertext: Vec<u8>,
}

pub fn content_file_slice_key(
    workspace_id: &WorkspaceId,
    file_id: &FactId,
    slice_index: u32,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 32 + 8);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(file_id);
    key.extend_from_slice(&u64::from(slice_index).to_be_bytes());
    key
}

pub fn content_file_slice_row(
    slice_fact_id: FactId,
    fact: &ContentFileSliceFact,
) -> Result<TableRow, String> {
    let ciphertext_len: u32 = fact
        .ciphertext
        .len()
        .try_into()
        .map_err(|_| "content file slice row ciphertext exceeds u32".to_string())?;
    let mut writer = wire::Writer::with_capacity(ROW_PREFIX_BYTES + fact.ciphertext.len());
    writer.fixed(&slice_fact_id);
    writer.u64be(fact.created_at_ms);
    writer.u32be(ciphertext_len);
    writer.bytes(&fact.ciphertext);
    Ok(TableRow {
        table: FILE_SLICE_ROWS,
        key: content_file_slice_key(&fact.workspace_id, &fact.file_id, fact.slice_index),
        value: writer.finish(),
    })
}

pub fn file_slice_rows_for_file(
    store: &Store,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_row_round_trips_ordered_key() {
        let fact = ContentFileSliceFact {
            workspace_id: [1; 32],
            created_at_ms: 77,
            file_id: [2; 32],
            slice_index: 5,
            ciphertext: vec![0xcc; 16],
        };
        let row = content_file_slice_row([9; 32], &fact).expect("row");
        assert_eq!(row.key, content_file_slice_key(&[1; 32], &[2; 32], 5));
        assert_eq!(&row.value[..32], &[9; 32]);
        assert_eq!(&row.value[44..], &[0xcc; 16]);
    }
}

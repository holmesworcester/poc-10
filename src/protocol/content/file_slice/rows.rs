//! Content-file-slice projection rows.
//!
//! Rows are keyed by `workspace_id || file_id || slice_index_be` so callers can
//! range-scan a file's slices in order without secondary indices. The value
//! stores the opaque ciphertext alongside the slice's fact id and timestamp.

use crate::core::facts::FactId;
use crate::core::intents::TableInsert;
use crate::core::intents::Value;
use crate::core::store::{Store, TableName};
use crate::protocol::registry::read_models;
use rusqlite::params;

use super::fact::{ContentFileSliceFact, WorkspaceId};

pub const FILE_SLICE_ROWS: TableName = read_models::FILE_SLICE_ROWS;
pub(crate) const FILE_SLICE_KEY_COLUMNS: &[&str] = read_models::FILE_SLICES.key_columns;
#[cfg(test)]
const FILE_SLICE_COLUMNS: &[&str] = read_models::FILE_SLICES.columns;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceRow {
    pub workspace_id: WorkspaceId,
    pub file_id: FactId,
    pub slice_index: u32,
    pub slice_fact_id: FactId,
    pub created_at_ms: u64,
    pub ciphertext: Vec<u8>,
}

pub fn content_file_slice_row(slice_fact_id: FactId, fact: &ContentFileSliceFact) -> TableInsert {
    read_models::FILE_SLICES.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(fact.file_id.to_vec()),
        Value::U64(u64::from(fact.slice_index)),
        Value::Bytes(slice_fact_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.ciphertext.bytes().to_vec()),
    ])
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
            ciphertext: crate::protocol::content::file_slice::fact::FileSliceCiphertext::new(
                &[0xcc; 16],
            )
            .expect("ciphertext"),
        };
        let row = content_file_slice_row([9; 32], &fact);
        assert_eq!(row.table, FILE_SLICE_ROWS);
        assert_eq!(row.columns, FILE_SLICE_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[2], Value::U64(5));
        assert_eq!(row.values[3], Value::Bytes(vec![9; 32]));
        assert_eq!(row.values[5], Value::Bytes(vec![0xcc; 16]));
    }
}

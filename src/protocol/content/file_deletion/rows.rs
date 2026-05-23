//! Content-file-deletion projection rows.
//!
//! Rows are keyed by `workspace_id || target_file_id` so the per-file purge
//! cascade can be authorized against the file's own author without a secondary
//! index. The value carries the deletion fact id, created_at_ms, and deletion
//! author. Per-file purge orchestration (slice tombstones, blob cleanup) lives
//! in a separate handler and is deferred.

use crate::core::facts::FactId;
use crate::core::intents::TableInsert;
use crate::core::intents::Value;
use crate::core::store::TableName;
use crate::protocol::registry::read_models;

use super::fact::{AuthorId, WorkspaceId};

pub const FILE_DELETION_ROWS: TableName = read_models::FILE_DELETION_ROWS;
#[cfg(test)]
const FILE_DELETION_COLUMNS: &[&str] = read_models::FILE_DELETIONS.columns;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDeletionRow {
    pub workspace_id: WorkspaceId,
    pub target_file_id: FactId,
    pub deletion_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
}

pub fn file_deletion_row(input: FileDeletionRow) -> TableInsert {
    read_models::FILE_DELETIONS.insert(vec![
        Value::Bytes(input.workspace_id.to_vec()),
        Value::Bytes(input.target_file_id.to_vec()),
        Value::Bytes(input.deletion_id.to_vec()),
        Value::U64(input.created_at_ms),
        Value::Bytes(input.author_user_id.to_vec()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_deletion_row_round_trips() {
        let input = FileDeletionRow {
            workspace_id: [1; 32],
            target_file_id: [2; 32],
            deletion_id: [3; 32],
            created_at_ms: 4_242,
            author_user_id: [4; 32],
        };
        let row = file_deletion_row(input);
        assert_eq!(row.table, FILE_DELETION_ROWS);
        assert_eq!(row.columns, FILE_DELETION_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[2], Value::Bytes(vec![3; 32]));
        assert_eq!(row.values[3], Value::U64(4_242));
        assert_eq!(row.values[4], Value::Bytes(vec![4; 32]));
    }
}

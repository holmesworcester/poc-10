//! Content-file projection rows.
//!
//! Rows are keyed by `workspace_id || file_fact_id` so callers can scan a
//! single workspace's file descriptors without secondary indices. The value
//! carries the public envelope plus the opaque sealed metadata; plaintext
//! filename/mime projection is deferred to a later slice that resolves the
//! per-file decryption secret.

use crate::core::facts::FactId;
use crate::core::intents::TableInsert;
use crate::core::intents::Value;
use crate::core::store::TableName;
use crate::protocol::registry::read_models;

use super::fact::{AuthorId, ContentFileFact, RootHash, WorkspaceId};

pub const FILE_ROWS: TableName = read_models::FILE_ROWS;
pub(crate) const FILE_KEY_COLUMNS: &[&str] = read_models::CONTENT_FILES.key_columns;
const FILE_COLUMNS: &[&str] = read_models::CONTENT_FILES.columns;

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

pub fn content_file_row(file_fact_id: FactId, fact: &ContentFileFact) -> TableInsert {
    read_models::CONTENT_FILES.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(file_fact_id.to_vec()),
        Value::Bytes(fact.message_id.to_vec()),
        Value::Bytes(fact.file_id.to_vec()),
        Value::Bytes(fact.author_user_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.root_hash.to_vec()),
        Value::U64(fact.blob_bytes),
        Value::U64(u64::from(fact.total_slices)),
        Value::U64(u64::from(fact.slice_bytes)),
        Value::Bytes(fact.sealed_metadata.clone()),
        Value::Bool(false),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_file_row_round_trips_workspace_keyed_value() {
        const ROOT_HASH_BYTES: usize = crate::protocol::content::file::fact::FILE_ROOT_HASH_BYTES;
        let fact = ContentFileFact {
            workspace_id: [1; 32],
            created_at_ms: 99,
            message_id: [2; 32],
            author_user_id: [3; 32],
            file_id: [4; 32],
            blob_bytes: 4096,
            total_slices: 1,
            slice_bytes: 4096,
            root_hash: [5; ROOT_HASH_BYTES],
            sealed_metadata: b"meta".to_vec(),
        };
        let row = content_file_row([7; 32], &fact);
        assert_eq!(row.table, FILE_ROWS);
        assert_eq!(row.columns, FILE_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![7; 32]));
        assert_eq!(row.values[2], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[3], Value::Bytes(vec![4; 32]));
        assert_eq!(row.values[4], Value::Bytes(vec![3; 32]));
        assert_eq!(row.values[6], Value::Bytes(vec![5; ROOT_HASH_BYTES]));
        assert_eq!(row.values[10], Value::Bytes(b"meta".to_vec()));
        assert_eq!(row.values[11], Value::Bool(false));
    }
}

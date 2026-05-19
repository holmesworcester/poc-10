//! Content-file projection rows.
//!
//! Rows are keyed by `workspace_id || file_fact_id` so callers can scan a
//! single workspace's file descriptors without secondary indices. The value
//! carries the public envelope plus the opaque sealed metadata; plaintext
//! filename/mime projection is deferred to a later slice that resolves the
//! per-file decryption secret.

use crate::core::facts::FactId;
use crate::core::schema_dsl::{self, FieldValue};
use crate::core::store::{TableName, TableRow};

use super::fact::{AuthorId, ContentFileFact, RootHash, WorkspaceId};

pub const FILE_ROWS: TableName = TableName::new("content_files");

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

pub fn content_file_key(workspace_id: &WorkspaceId, file_fact_id: &FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(file_fact_id);
    key
}

pub fn content_file_row(file_fact_id: FactId, fact: &ContentFileFact) -> Result<TableRow, String> {
    schema_dsl::encode_table_row(
        FILE_ROWS,
        schema_dsl::facts_table("content_files"),
        &[
            (
                "workspace_id",
                FieldValue::Bytes(fact.workspace_id.to_vec()),
            ),
            ("file_fact_id", FieldValue::Bytes(file_fact_id.to_vec())),
            ("message_id", FieldValue::Bytes(fact.message_id.to_vec())),
            ("file_id", FieldValue::Bytes(fact.file_id.to_vec())),
            (
                "author_user_id",
                FieldValue::Bytes(fact.author_user_id.to_vec()),
            ),
            ("created_at_ms", FieldValue::U64(fact.created_at_ms)),
            ("root_hash", FieldValue::Bytes(fact.root_hash.to_vec())),
            ("byte_len", FieldValue::U64(fact.blob_bytes)),
            (
                "total_slices",
                FieldValue::U64(u64::from(fact.total_slices)),
            ),
            ("slice_bytes", FieldValue::U64(u64::from(fact.slice_bytes))),
            (
                "sealed_metadata",
                FieldValue::Bytes(fact.sealed_metadata.clone()),
            ),
            ("deleted", FieldValue::Bool(false)),
        ],
    )
}

pub fn decode_content_file_row(key: &[u8], value: &[u8]) -> Result<ContentFileRow, String> {
    let record =
        schema_dsl::decode_table_row(schema_dsl::facts_table("content_files"), key, value)?;
    if record.bool("deleted")? {
        return Err("content file row is deleted".to_string());
    }
    Ok(ContentFileRow {
        workspace_id: record.bytes_array("workspace_id")?,
        file_fact_id: record.bytes_array("file_fact_id")?,
        created_at_ms: record.u64("created_at_ms")?,
        message_id: record.bytes_array("message_id")?,
        author_user_id: record.bytes_array("author_user_id")?,
        file_id: record.bytes_array("file_id")?,
        blob_bytes: record.u64("byte_len")?,
        total_slices: record
            .u64("total_slices")?
            .try_into()
            .map_err(|_| "content file row total_slices exceeds u32".to_string())?,
        slice_bytes: record
            .u64("slice_bytes")?
            .try_into()
            .map_err(|_| "content file row slice_bytes exceeds u32".to_string())?,
        root_hash: record.bytes_array("root_hash")?,
        sealed_metadata: record.bytes_vec("sealed_metadata")?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::fact::FILE_ROOT_HASH_BYTES;
    use super::*;

    #[test]
    fn content_file_row_round_trips_workspace_keyed_value() {
        let fact = ContentFileFact {
            workspace_id: [1; 32],
            created_at_ms: 99,
            message_id: [2; 32],
            author_user_id: [3; 32],
            file_id: [4; 32],
            blob_bytes: 4096,
            total_slices: 1,
            slice_bytes: 4096,
            root_hash: [5; FILE_ROOT_HASH_BYTES],
            sealed_metadata: b"meta".to_vec(),
        };
        let row = content_file_row([7; 32], &fact).expect("row");
        assert_eq!(row.key, content_file_key(&[1; 32], &[7; 32]));
        let decoded = decode_content_file_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.file_fact_id, [7; 32]);
        assert_eq!(decoded.sealed_metadata, b"meta");
        assert_eq!(decoded.blob_bytes, 4096);
        assert_eq!(decoded.total_slices, 1);
        assert_eq!(decoded.slice_bytes, 4096);
        assert_eq!(decoded.root_hash, [5; FILE_ROOT_HASH_BYTES]);
    }
}

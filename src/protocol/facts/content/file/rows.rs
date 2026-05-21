//! Content-file projection rows.
//!
//! Rows are keyed by `workspace_id || file_fact_id` so callers can scan a
//! single workspace's file descriptors without secondary indices. The value
//! carries the public envelope plus the opaque sealed metadata; plaintext
//! filename/mime projection is deferred to a later slice that resolves the
//! per-file decryption secret.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use super::fact::{AuthorId, ContentFileFact, RootHash, WorkspaceId, FILE_ROOT_HASH_BYTES};

pub const FILE_ROWS: TableName = TableName::new("content_files");
pub const ROW_PREFIX_BYTES: usize = 32 + 32 + 32 + 8 + FILE_ROOT_HASH_BYTES + 8 + 8 + 8 + 4;

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
    let sealed_len: u32 = fact
        .sealed_metadata
        .len()
        .try_into()
        .map_err(|_| "content file row sealed metadata exceeds u32".to_string())?;
    let mut writer = wire::Writer::with_capacity(ROW_PREFIX_BYTES + fact.sealed_metadata.len() + 1);
    writer.fixed(&fact.message_id);
    writer.fixed(&fact.file_id);
    writer.fixed(&fact.author_user_id);
    writer.u64be(fact.created_at_ms);
    writer.fixed(&fact.root_hash);
    writer.u64be(fact.blob_bytes);
    writer.u64be(u64::from(fact.total_slices));
    writer.u64be(u64::from(fact.slice_bytes));
    writer.u32be(sealed_len);
    writer.bytes(&fact.sealed_metadata);
    writer.u8(0);
    Ok(TableRow {
        table: FILE_ROWS,
        key: content_file_key(&fact.workspace_id, &file_fact_id),
        value: writer.finish(),
    })
}

#[cfg(test)]
mod tests {
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
        assert_eq!(&row.value[..32], &[2; 32]);
        assert_eq!(&row.value[32..64], &[4; 32]);
        assert_eq!(&row.value[64..96], &[3; 32]);
        assert_eq!(&row.value[104..136], &[5; FILE_ROOT_HASH_BYTES]);
        assert!(row.value.ends_with(&[b'm', b'e', b't', b'a', 0]));
    }
}

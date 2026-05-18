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

pub const FILE_ROWS: TableName = TableName::new("file_rows");
pub const ROW_PREFIX_BYTES: usize = 1 + 8 + 32 + 32 + 32 + 8 + 4 + 4 + FILE_ROOT_HASH_BYTES + 4;
const ROW_VERSION: u8 = 1;

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
    let mut writer = wire::Writer::with_capacity(ROW_PREFIX_BYTES + fact.sealed_metadata.len());
    writer.u8(ROW_VERSION);
    writer.u64be(fact.created_at_ms);
    writer.fixed(&fact.message_id);
    writer.fixed(&fact.author_user_id);
    writer.fixed(&fact.file_id);
    writer.u64be(fact.blob_bytes);
    writer.u32be(fact.total_slices);
    writer.u32be(fact.slice_bytes);
    writer.fixed(&fact.root_hash);
    writer.u32be(sealed_len);
    writer.bytes(&fact.sealed_metadata);
    Ok(TableRow {
        table: FILE_ROWS,
        key: content_file_key(&fact.workspace_id, &file_fact_id),
        value: writer.finish(),
    })
}

pub fn decode_content_file_row(key: &[u8], value: &[u8]) -> Result<ContentFileRow, String> {
    if key.len() != 64 {
        return Err("content file row key is malformed".to_string());
    }
    if value.len() < ROW_PREFIX_BYTES || value[0] != ROW_VERSION {
        return Err("content file row value is malformed".to_string());
    }
    let mut value_reader = wire::Reader::new(value);
    let version = value_reader.u8().map_err(wire_err)?;
    if version != ROW_VERSION {
        return Err("content file row value is malformed".to_string());
    }
    let created_at_ms = value_reader.u64be().map_err(wire_err)?;
    let message_id = value_reader.array().map_err(wire_err)?;
    let author_user_id = value_reader.array().map_err(wire_err)?;
    let file_id = value_reader.array().map_err(wire_err)?;
    let blob_bytes = value_reader.u64be().map_err(wire_err)?;
    let total_slices = value_reader.u32be().map_err(wire_err)?;
    let slice_bytes = value_reader.u32be().map_err(wire_err)?;
    let root_hash = value_reader.array().map_err(wire_err)?;
    let sealed_len = value_reader.u32be().map_err(wire_err)? as usize;
    if value.len() != ROW_PREFIX_BYTES + sealed_len {
        return Err("content file row value length does not match metadata".to_string());
    }
    let sealed_metadata = value_reader.bytes(sealed_len).map_err(wire_err)?.to_vec();
    value_reader.finish().map_err(wire_err)?;
    let mut key_reader = wire::Reader::new(key);
    let workspace_id = key_reader.array().map_err(wire_err)?;
    let file_fact_id = key_reader.array().map_err(wire_err)?;
    key_reader.finish().map_err(wire_err)?;
    Ok(ContentFileRow {
        workspace_id,
        file_fact_id,
        created_at_ms,
        message_id,
        author_user_id,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        sealed_metadata,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
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
        let decoded = decode_content_file_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.file_fact_id, [7; 32]);
        assert_eq!(decoded.sealed_metadata, b"meta");
        assert_eq!(decoded.blob_bytes, 4096);
        assert_eq!(decoded.total_slices, 1);
        assert_eq!(decoded.slice_bytes, 4096);
        assert_eq!(decoded.root_hash, [5; FILE_ROOT_HASH_BYTES]);
    }
}

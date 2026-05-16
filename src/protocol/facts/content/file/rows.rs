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
pub const ROW_HEADER_BYTES: usize = 1 + 8 + 32 + 32 + 32 + 8 + 4 + 4 + FILE_ROOT_HASH_BYTES + 4;
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
    let mut value = vec![0; ROW_HEADER_BYTES + fact.sealed_metadata.len()];
    value[0] = ROW_VERSION;
    wire::put_u64be(fact.created_at_ms, &mut value[1..9]).map_err(wire_err)?;
    value[9..41].copy_from_slice(&fact.message_id);
    value[41..73].copy_from_slice(&fact.author_user_id);
    value[73..105].copy_from_slice(&fact.file_id);
    wire::put_u64be(fact.blob_bytes, &mut value[105..113]).map_err(wire_err)?;
    wire::put_u32be(fact.total_slices, &mut value[113..117]).map_err(wire_err)?;
    wire::put_u32be(fact.slice_bytes, &mut value[117..121]).map_err(wire_err)?;
    value[121..153].copy_from_slice(&fact.root_hash);
    wire::put_u32be(sealed_len, &mut value[153..157]).map_err(wire_err)?;
    value[ROW_HEADER_BYTES..].copy_from_slice(&fact.sealed_metadata);
    Ok(TableRow {
        table: FILE_ROWS,
        key: content_file_key(&fact.workspace_id, &file_fact_id),
        value,
    })
}

pub fn decode_content_file_row(key: &[u8], value: &[u8]) -> Result<ContentFileRow, String> {
    if key.len() != 64 {
        return Err("content file row key is malformed".to_string());
    }
    if value.len() < ROW_HEADER_BYTES || value[0] != ROW_VERSION {
        return Err("content file row value is malformed".to_string());
    }
    let sealed_len = wire::take_u32be(&value[153..157]).map_err(wire_err)? as usize;
    if value.len() != ROW_HEADER_BYTES + sealed_len {
        return Err("content file row value length does not match metadata".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut file_fact_id = [0; 32];
    file_fact_id.copy_from_slice(&key[32..64]);
    Ok(ContentFileRow {
        workspace_id,
        file_fact_id,
        created_at_ms: wire::take_u64be(&value[1..9]).map_err(wire_err)?,
        message_id: value[9..41].try_into().unwrap(),
        author_user_id: value[41..73].try_into().unwrap(),
        file_id: value[73..105].try_into().unwrap(),
        blob_bytes: wire::take_u64be(&value[105..113]).map_err(wire_err)?,
        total_slices: wire::take_u32be(&value[113..117]).map_err(wire_err)?,
        slice_bytes: wire::take_u32be(&value[117..121]).map_err(wire_err)?,
        root_hash: value[121..153].try_into().unwrap(),
        sealed_metadata: value[ROW_HEADER_BYTES..].to_vec(),
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

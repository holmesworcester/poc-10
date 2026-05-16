//! Content-file-slice projection rows.
//!
//! Rows are keyed by `workspace_id || file_id || slice_index_be` so callers can
//! range-scan a file's slices in order without secondary indices. The value
//! stores the opaque ciphertext alongside the slice's fact id and timestamp.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use super::fact::{ContentFileSliceFact, WorkspaceId};

pub const FILE_SLICE_ROWS: TableName = TableName::new("file_slice_rows");
pub const ROW_HEADER_BYTES: usize = 1 + 8 + 32 + 4;
const ROW_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFileSliceRow {
    pub workspace_id: WorkspaceId,
    pub file_id: FactId,
    pub slice_index: u32,
    pub slice_event_id: FactId,
    pub created_at_ms: u64,
    pub ciphertext: Vec<u8>,
}

pub fn content_file_slice_key(
    workspace_id: &WorkspaceId,
    file_id: &FactId,
    slice_index: u32,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 32 + 4);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(file_id);
    key.extend_from_slice(&slice_index.to_be_bytes());
    key
}

pub fn content_file_slice_row(
    slice_event_id: FactId,
    fact: &ContentFileSliceFact,
) -> Result<TableRow, String> {
    let ciphertext_len: u32 = fact
        .ciphertext
        .len()
        .try_into()
        .map_err(|_| "content file slice row ciphertext exceeds u32".to_string())?;
    let mut value = vec![0; ROW_HEADER_BYTES + fact.ciphertext.len()];
    value[0] = ROW_VERSION;
    wire::put_u64be(fact.created_at_ms, &mut value[1..9]).map_err(wire_err)?;
    value[9..41].copy_from_slice(&slice_event_id);
    wire::put_u32be(ciphertext_len, &mut value[41..45]).map_err(wire_err)?;
    value[ROW_HEADER_BYTES..].copy_from_slice(&fact.ciphertext);
    Ok(TableRow {
        table: FILE_SLICE_ROWS,
        key: content_file_slice_key(&fact.workspace_id, &fact.file_id, fact.slice_index),
        value,
    })
}

pub fn decode_content_file_slice_row(
    key: &[u8],
    value: &[u8],
) -> Result<ContentFileSliceRow, String> {
    if key.len() != 32 + 32 + 4 {
        return Err("content file slice row key is malformed".to_string());
    }
    if value.len() < ROW_HEADER_BYTES || value[0] != ROW_VERSION {
        return Err("content file slice row value is malformed".to_string());
    }
    let ciphertext_len = wire::take_u32be(&value[41..45]).map_err(wire_err)? as usize;
    if value.len() != ROW_HEADER_BYTES + ciphertext_len {
        return Err("content file slice row value length does not match ciphertext".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut file_id = [0; 32];
    file_id.copy_from_slice(&key[32..64]);
    let slice_index = u32::from_be_bytes(key[64..68].try_into().unwrap());
    Ok(ContentFileSliceRow {
        workspace_id,
        file_id,
        slice_index,
        slice_event_id: value[9..41].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&value[1..9]).map_err(wire_err)?,
        ciphertext: value[ROW_HEADER_BYTES..].to_vec(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
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
        let decoded = decode_content_file_slice_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.file_id, [2; 32]);
        assert_eq!(decoded.slice_index, 5);
        assert_eq!(decoded.slice_event_id, [9; 32]);
        assert_eq!(decoded.created_at_ms, 77);
        assert_eq!(decoded.ciphertext, vec![0xcc; 16]);
    }
}

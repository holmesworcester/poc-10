//! Projection row layouts for accepted key-wrap state.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::KeyWrapFact;
use super::layout::{self, KEY_WRAP_BYTES};

pub const KEY_WRAP_ROWS: TableName = TableName::new("key_wrap_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapRow {
    pub key_wrap_id: FactId,
    pub signer_public_key: [u8; 32],
    pub wrap: KeyWrapFact,
}

pub fn key_wrap_row(input: KeyWrapRow) -> Result<TableRow, String> {
    let mut value = Vec::with_capacity(1 + 32 + 32 + KEY_WRAP_BYTES);
    value.push(1);
    value.extend_from_slice(&input.key_wrap_id);
    value.extend_from_slice(&input.signer_public_key);
    value.extend_from_slice(&layout::encode_key_wrap(&input.wrap)?);
    Ok(TableRow {
        table: KEY_WRAP_ROWS,
        key: layout::key_wrap_coordinate_key(&input.wrap)?,
        value,
    })
}

pub fn decode_key_wrap_row(key: &[u8], value: &[u8]) -> Result<KeyWrapRow, String> {
    if key.len() != layout::KEY_WRAP_COORDINATE_KEY_BYTES {
        return Err("key wrap row key is malformed".to_string());
    }
    if value.len() != 1 + 32 + 32 + KEY_WRAP_BYTES || value[0] != 1 {
        return Err("invalid key wrap row value".to_string());
    }
    let wrap = layout::decode_key_wrap(&value[65..])?;
    if key != layout::key_wrap_coordinate_key(&wrap)? {
        return Err("key wrap row key does not match value".to_string());
    }
    Ok(KeyWrapRow {
        key_wrap_id: value[1..33].try_into().unwrap(),
        signer_public_key: value[33..65].try_into().unwrap(),
        wrap,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::protocol::facts::encryption::fact::{KeyWrapFact, WrappedSecretKind};

    #[test]
    fn accepted_key_wrap_row_round_trips_by_coordinate() {
        let wrap = KeyWrapFact {
            workspace_id: [1; 32],
            created_at_ms: 2,
            signer_endpoint_id: [3; 32],
            frontier_id: [4; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: [5; 32],
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            recipient_key_id: [6; 32],
            sender_wrap_public_key: [7; 32],
            nonce: [8; 24],
            ciphertext: [9; 48],
        };
        let row = KeyWrapRow {
            key_wrap_id: [10; 32],
            signer_public_key: [11; 32],
            wrap,
        };
        let table_row = key_wrap_row(row.clone()).expect("row");

        assert_eq!(table_row.table, KEY_WRAP_ROWS);
        assert_eq!(
            decode_key_wrap_row(&table_row.key, &table_row.value).expect("decode"),
            row
        );
    }
}

//! Read-only decoding for accepted key-wrap projection rows.
//!
//! Query helpers are the only key_wrap module functions that inspect projected
//! row state directly. They decode the wrap embedded in the row value and prove
//! that the stored coordinate key matches it. They never write, construct facts,
//! project, or dispatch intents.

use crate::core::facts::FactId;

use super::encode;
use super::fact::KeyWrapFact;
use super::{decode, KEY_WRAP_ROW_SCHEMA};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapRow {
    pub key_wrap_id: FactId,
    pub signer_public_key: [u8; 32],
    pub wrap: KeyWrapFact,
}

pub fn decode_key_wrap_row(key: &[u8], value: &[u8]) -> Result<KeyWrapRow, String> {
    let value_fields = KEY_WRAP_ROW_SCHEMA.decode_value(value)?;
    if value_fields[0].as_u8("version")? != 1 {
        return Err("invalid key wrap row value".to_string());
    }
    let key_wrap_id = value_fields[1].as_bytes32("key_wrap_id")?;
    let signer_public_key = value_fields[2].as_bytes32("signer_public_key")?;
    let wrap = decode::decode_key_wrap(value_fields[3].as_bytes("wrap")?)?;
    if key != encode::key_wrap_coordinate_key(&wrap)? {
        return Err("key wrap row key does not match value".to_string());
    }
    Ok(KeyWrapRow {
        key_wrap_id,
        signer_public_key,
        wrap,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::key_wrap::fact::WrappedSecretKind;
    use crate::protocol::auth::key_wrap::key_wrap_row;

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

        assert_eq!(table_row.table, super::super::KEY_WRAP_ROWS);
        assert_eq!(
            decode_key_wrap_row(&table_row.key, &table_row.value).expect("decode"),
            row
        );
    }
}

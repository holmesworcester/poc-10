//! Read-only decoding and lookups for connection fact-receipt origin rows.
//!
//! These rows are a narrow efficiency hint for sync live-tail egress. They say
//! which established connection delivered a fact when that is known; they do not
//! authorize the received payload or replace projector receipt validation.
//! Query helpers decode that row state and never write, construct facts,
//! project, or dispatch intents.

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::{CONNECTION_FACT_RECEIPT_ROWS, CONNECTION_FACT_RECEIPT_ROW_SCHEMA};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFactReceiptRow {
    pub received_fact_id: FactId,
    pub receipt_fact_id: FactId,
    pub connection_id: Option<FactId>,
}

pub fn decode_connection_fact_receipt_row(
    key: &[u8],
    value: &[u8],
) -> Result<ConnectionFactReceiptRow, String> {
    let key_fields = CONNECTION_FACT_RECEIPT_ROW_SCHEMA.decode_key(key)?;
    let value_fields = CONNECTION_FACT_RECEIPT_ROW_SCHEMA.decode_value(value)?;
    if value_fields[0].as_u8("present")? != 1 {
        return Err("invalid connection fact receipt row value".into());
    }
    let raw_connection_id = value_fields[2].as_bytes32("connection_id")?;
    let connection_id = match value_fields[1].as_u8("has_connection")? {
        0 => {
            if raw_connection_id != [0; 32] {
                return Err("connection fact receipt row none connection must be zero".into());
            }
            None
        }
        1 => Some(raw_connection_id),
        _ => return Err("invalid connection fact receipt row connection flag".into()),
    };
    Ok(ConnectionFactReceiptRow {
        received_fact_id: key_fields[0].as_bytes32("received_fact_id")?,
        receipt_fact_id: key_fields[1].as_bytes32("receipt_fact_id")?,
        connection_id,
    })
}

pub fn origin_connection_ids_for_fact(
    store: &Store,
    received_fact_id: FactId,
) -> Result<Vec<FactId>, String> {
    let mut ids = store
        .table_rows_with_key_prefix(CONNECTION_FACT_RECEIPT_ROWS, &received_fact_id, usize::MAX)
        .map_err(|err| format!("load connection fact receipt rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_connection_fact_receipt_row(&key, &value))
        .map(|row| row.map(|row| row.connection_id))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::connection::fact_receipt::fact::{
        ConnectionFactReceipt, OriginAddr, RECEIVE_PATH_CONNECTION,
    };

    fn receipt(connection_id: Option<FactId>) -> ConnectionFactReceipt {
        ConnectionFactReceipt {
            received_fact_id: [1; 32],
            origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
            local_endpoint_id: [3; 32],
            sender_endpoint_id: [4; 32],
            receive_path: RECEIVE_PATH_CONNECTION,
            connection_id,
            request_id: Some([5; 32]),
            frame_hash: [6; 32],
            received_at_local_ms: 55,
        }
    }

    #[test]
    fn connection_fact_receipt_row_roundtrips_through_schema() {
        let row = super::super::connection_fact_receipt_row([2; 32], &receipt(Some([7; 32])))
            .expect("receipt row");
        let decoded =
            decode_connection_fact_receipt_row(&row.key, &row.value).expect("decode receipt row");
        assert_eq!(decoded.received_fact_id, [1; 32]);
        assert_eq!(decoded.receipt_fact_id, [2; 32]);
        assert_eq!(decoded.connection_id, Some([7; 32]));
    }

    #[test]
    fn connection_fact_receipt_row_roundtrips_without_connection() {
        let row = super::super::connection_fact_receipt_row([2; 32], &receipt(None))
            .expect("receipt row");
        let decoded =
            decode_connection_fact_receipt_row(&row.key, &row.value).expect("decode receipt row");
        assert_eq!(decoded.connection_id, None);
    }
}

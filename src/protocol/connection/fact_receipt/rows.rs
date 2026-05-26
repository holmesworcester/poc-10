//! Durable receipt-origin rows.
//!
//! These rows are a narrow efficiency hint for sync live-tail egress. They say
//! which established connection delivered a fact when that is known; they do
//! not authorize the received payload or replace projector receipt validation.

use crate::core::facts::FactId;
use crate::core::store::{Store, TableName, TableRow};

pub const CONNECTION_FACT_RECEIPT_ROWS: TableName = TableName::new("connection_fact_receipt_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFactReceiptRow {
    pub received_fact_id: FactId,
    pub receipt_fact_id: FactId,
    pub connection_id: Option<FactId>,
}

pub fn connection_fact_receipt_row(
    receipt_fact_id: FactId,
    receipt: &super::fact::ConnectionFactReceipt,
) -> TableRow {
    let mut value = Vec::with_capacity(34);
    value.push(1);
    match receipt.connection_id {
        Some(connection_id) => {
            value.push(1);
            value.extend_from_slice(&connection_id);
        }
        None => {
            value.push(0);
            value.extend_from_slice(&[0; 32]);
        }
    }
    TableRow {
        table: CONNECTION_FACT_RECEIPT_ROWS,
        key: connection_fact_receipt_key(receipt.received_fact_id, receipt_fact_id),
        value,
    }
}

pub fn decode_connection_fact_receipt_row(
    key: &[u8],
    value: &[u8],
) -> Result<ConnectionFactReceiptRow, String> {
    if key.len() != 64 {
        return Err("connection fact receipt row key must be received id plus receipt id".into());
    }
    if value.len() != 34 || value[0] != 1 {
        return Err("invalid connection fact receipt row value".into());
    }
    let raw_connection_id: FactId = value[2..34].try_into().unwrap();
    let connection_id = match value[1] {
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
        received_fact_id: key[..32].try_into().unwrap(),
        receipt_fact_id: key[32..64].try_into().unwrap(),
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

fn connection_fact_receipt_key(received_fact_id: FactId, receipt_fact_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&received_fact_id);
    key.extend_from_slice(&receipt_fact_id);
    key
}

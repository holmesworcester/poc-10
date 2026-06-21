//! Connection fact-receipt family.
//!
//! A fact receipt is durable local evidence that a semantic fact entered this
//! node through the connection protocol. Receipts record normalized origin
//! metadata, receive time, receive path, and optional connection/request
//! witnesses; they publish context keyed by the received fact id.
//!
//! Receipts do not authorize the received payload. The semantic projector for
//! the received fact decides whether the receipt proves the right path. Change
//! this family for receipt bytes, receive-path vocabulary, or receipt context
//! offers.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub use queries::origin_connection_ids_for_fact;

/// Durable receipt-origin rows, keyed by `received_fact_id || receipt_fact_id`.
/// They are a narrow efficiency hint for sync live-tail egress: they say which
/// established connection delivered a fact when that is known; they do not
/// authorize the received payload or replace projector receipt validation.
pub const CONNECTION_FACT_RECEIPT_ROWS: TableName = TableName::new("connection_fact_receipt_rows");

pub const CONNECTION_FACT_RECEIPT_COLUMNS: &[&str] = &[
    "received_fact_id",
    "receipt_fact_id",
    "has_connection",
    "connection_id",
];
pub const CONNECTION_FACT_RECEIPT_KEY_COLUMNS: &[&str] = &["received_fact_id", "receipt_fact_id"];
pub const CONNECTION_FACT_RECEIPT_TABLE: TypedTableSchema = TypedTableSchema {
    table: CONNECTION_FACT_RECEIPT_ROWS,
    columns: CONNECTION_FACT_RECEIPT_COLUMNS,
    key_columns: CONNECTION_FACT_RECEIPT_KEY_COLUMNS,
};

pub fn connection_fact_receipt_row(
    receipt_fact_id: FactId,
    receipt: &fact::ConnectionFactReceipt,
) -> Result<TableInsert, String> {
    let (has_connection, connection_id) = match receipt.connection_id {
        Some(connection_id) => (1, connection_id),
        None => (0, [0; 32]),
    };
    Ok(CONNECTION_FACT_RECEIPT_TABLE.insert(vec![
        Value::Bytes(receipt.received_fact_id.to_vec()),
        Value::Bytes(receipt_fact_id.to_vec()),
        Value::U64(has_connection),
        Value::Bytes(connection_id.to_vec()),
    ]))
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionFactReceipt, String> {
    project::decode::decode_fact(bytes)
}

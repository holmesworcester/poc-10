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

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub use queries::origin_connection_ids_for_fact;

/// Durable receipt-origin rows, keyed by `received_fact_id || receipt_fact_id`.
/// They are a narrow efficiency hint for sync live-tail egress: they say which
/// established connection delivered a fact when that is known; they do not
/// authorize the received payload or replace projector receipt validation.
pub const CONNECTION_FACT_RECEIPT_ROWS: TableName = TableName::new("connection_fact_receipt_rows");

const CONNECTION_FACT_RECEIPT_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("received_fact_id"),
    RowField::bytes32("receipt_fact_id"),
];
const CONNECTION_FACT_RECEIPT_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u8("present"),
    RowField::u8("has_connection"),
    RowField::bytes32("connection_id"),
];

pub const CONNECTION_FACT_RECEIPT_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    CONNECTION_FACT_RECEIPT_ROWS,
    CONNECTION_FACT_RECEIPT_ROW_KEY_FIELDS,
    CONNECTION_FACT_RECEIPT_ROW_VALUE_FIELDS,
);

pub fn connection_fact_receipt_row(
    receipt_fact_id: FactId,
    receipt: &fact::ConnectionFactReceipt,
) -> Result<TableRow, String> {
    let (has_connection, connection_id) = match receipt.connection_id {
        Some(connection_id) => (1, connection_id),
        None => (0, [0; 32]),
    };
    CONNECTION_FACT_RECEIPT_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(receipt.received_fact_id.to_vec()),
            RowValue::Bytes(receipt_fact_id.to_vec()),
        ],
        &[
            RowValue::U8(1),
            RowValue::U8(has_connection),
            RowValue::Bytes(connection_id.to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionFactReceipt, String> {
    decode::decode_fact(bytes)
}

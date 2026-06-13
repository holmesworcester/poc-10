//! Sync need-id fact family.
//!
//! Need-id facts request a specific fact from a peer after compare or have-id
//! planning discovers a gap. Projection records the request and emits handler
//! work to send the fact when this store has it. The requested payload remains
//! validated by its owning fact family after receipt.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub const TYPE_SYNC_NEED_ID: u8 = encode::TYPE_SYNC_NEED_ID;

/// Sync need-id projection rows, keyed by `connection_id || fact_id`; the value
/// stores the requested fact id. Keeping the fact id in the key keeps repeated
/// needs for the same fact id distinct across compare rounds.
pub const SYNC_NEED_ID_ROWS: TableName = TableName::new("sync_need_id_rows");

const SYNC_NEED_ID_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("connection_id"),
    RowField::bytes32("fact_id"),
];
const SYNC_NEED_ID_ROW_VALUE_FIELDS: &[RowField] = &[RowField::bytes32("requested_fact_id")];

pub const SYNC_NEED_ID_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    SYNC_NEED_ID_ROWS,
    SYNC_NEED_ID_ROW_KEY_FIELDS,
    SYNC_NEED_ID_ROW_VALUE_FIELDS,
);

pub fn sync_need_id_row(
    row_fact_id: FactId,
    fact: &fact::SyncNeedIdFact,
) -> Result<TableRow, String> {
    SYNC_NEED_ID_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.connection_id.to_vec()),
            RowValue::Bytes(row_fact_id.to_vec()),
        ],
        &[RowValue::Bytes(fact.fact_id.to_vec())],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncNeedIdFact, String> {
    project::decode::decode_fact(bytes)
}

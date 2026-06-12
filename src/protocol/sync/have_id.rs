//! Sync have-id fact family.
//!
//! A have-id fact tells a peer that this connection can provide a specific
//! fact id at a timestamp. Projection records the advertisement and wakes any
//! matching need-id flow. The helper here builds advertisements from already
//! stored facts; it does not validate the advertised fact's own protocol
//! semantics.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

pub use author::advertisement_fact;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub(crate) use decode::Codec;

pub const TYPE_SYNC_HAVE_ID: u8 = encode::TYPE_SYNC_HAVE_ID;

/// Sync have-id projection rows, keyed by `connection_id || fact_id` so
/// connection frame send handlers can scan all advertisements queued for a
/// connection. The value stores the timestamp and the advertised fact id; the
/// fact id in the key keeps distinct advertisements distinct even when the same
/// fact id is re-advertised from a later range compare.
pub const SYNC_HAVE_ID_ROWS: TableName = TableName::new("sync_have_id_rows");

const SYNC_HAVE_ID_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("connection_id"),
    RowField::bytes32("fact_id"),
];
const SYNC_HAVE_ID_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("timestamp"),
    RowField::bytes32("advertised_fact_id"),
];

pub const SYNC_HAVE_ID_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    SYNC_HAVE_ID_ROWS,
    SYNC_HAVE_ID_ROW_KEY_FIELDS,
    SYNC_HAVE_ID_ROW_VALUE_FIELDS,
);

pub fn sync_have_id_row(
    row_fact_id: FactId,
    fact: &fact::SyncHaveIdFact,
) -> Result<TableRow, String> {
    SYNC_HAVE_ID_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.connection_id.to_vec()),
            RowValue::Bytes(row_fact_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.timestamp),
            RowValue::Bytes(fact.fact_id.to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncHaveIdFact, String> {
    decode::decode_fact(bytes)
}

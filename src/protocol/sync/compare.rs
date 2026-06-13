//! Sync compare fact family.
//!
//! Compare facts summarize a timestamp range for one connection. Projection
//! records the inbound compare and emits response work when requested; create
//! helpers build initial compares, split mismatched ranges, and choose exact
//! fact-id sends when a range is small enough. This module owns the negentropy
//! planning surface for sync.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub const TYPE_SYNC_COMPARE: u8 = encode::TYPE_SYNC_COMPARE;

/// Sync compare projection rows, keyed by `connection_id || fact_id` so
/// connection frame send handlers can scan a single connection's outstanding
/// compare queries. The value stores the timestamp range, the summary (count +
/// fingerprint), and the response-requested flag.
pub const SYNC_COMPARE_ROWS: TableName = TableName::new("sync_compare_rows");

const SYNC_COMPARE_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("connection_id"),
    RowField::bytes32("fact_id"),
];
const SYNC_COMPARE_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("range_start"),
    RowField::u64be("range_end"),
    RowField::u64be("count"),
    RowField::bytes32("fingerprint"),
    RowField::u8("response_requested"),
];

pub const SYNC_COMPARE_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    SYNC_COMPARE_ROWS,
    SYNC_COMPARE_ROW_KEY_FIELDS,
    SYNC_COMPARE_ROW_VALUE_FIELDS,
);

pub fn sync_compare_row(fact_id: FactId, fact: &fact::SyncCompareFact) -> Result<TableRow, String> {
    SYNC_COMPARE_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.connection_id.to_vec()),
            RowValue::Bytes(fact_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.range.start),
            RowValue::U64(fact.range.end),
            RowValue::U64(fact.summary.count),
            RowValue::Bytes(fact.summary.fingerprint.to_vec()),
            RowValue::U8(u8::from(fact.response_requested)),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncCompareFact, String> {
    project::decode::decode_fact(bytes)
}

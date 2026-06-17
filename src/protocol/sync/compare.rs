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

use crate::core::facts::FactId;
use crate::core::store::{TableInsert, TableName, TypedTableSchema, Value};

pub const TYPE_SYNC_COMPARE: u8 = encode::TYPE_SYNC_COMPARE;

/// Sync compare projection rows, keyed by `connection_id || fact_id` so
/// connection frame send handlers can scan a single connection's outstanding
/// compare queries. The value stores the timestamp range, the summary (count +
/// fingerprint), and the response-requested flag.
pub const SYNC_COMPARE_ROWS: TableName = TableName::new("sync_compare_rows");

pub const SYNC_COMPARE_COLUMNS: &[&str] = &[
    "connection_id",
    "fact_id",
    "range_start",
    "range_end",
    "count",
    "fingerprint",
    "response_requested",
];
pub const SYNC_COMPARE_KEY_COLUMNS: &[&str] = &["connection_id", "fact_id"];
pub const SYNC_COMPARE_TABLE: TypedTableSchema = TypedTableSchema {
    table: SYNC_COMPARE_ROWS,
    columns: SYNC_COMPARE_COLUMNS,
    key_columns: SYNC_COMPARE_KEY_COLUMNS,
};

pub fn sync_compare_row(fact_id: FactId, fact: &fact::SyncCompareFact) -> TableInsert {
    SYNC_COMPARE_TABLE.insert(vec![
        Value::Bytes(fact.connection_id.to_vec()),
        Value::Bytes(fact_id.to_vec()),
        Value::Bytes(fact.range.start.to_be_bytes().to_vec()),
        Value::Bytes(fact.range.end.to_be_bytes().to_vec()),
        Value::U64(fact.summary.count),
        Value::Bytes(fact.summary.fingerprint.to_vec()),
        Value::U64(u64::from(u8::from(fact.response_requested))),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncCompareFact, String> {
    project::decode::decode_fact(bytes)
}

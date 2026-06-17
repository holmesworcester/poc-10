//! Sync have-id fact family.
//!
//! A have-id fact tells a peer that this connection can provide a specific
//! fact id at a timestamp. Projection records the advertisement and wakes any
//! matching need-id flow. The helper here builds advertisements from already
//! stored facts; it does not validate the advertised fact's own protocol
//! semantics.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;

pub use author::advertisement_fact;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_SYNC_HAVE_ID: u8 = encode::TYPE_SYNC_HAVE_ID;

/// Sync have-id projection rows, keyed by `connection_id || fact_id` so
/// connection frame send handlers can scan all advertisements queued for a
/// connection. The value stores the timestamp and the advertised fact id; the
/// fact id in the key keeps distinct advertisements distinct even when the same
/// fact id is re-advertised from a later range compare.
pub const SYNC_HAVE_ID_ROWS: TableName = TableName::new("sync_have_id_rows");

pub const SYNC_HAVE_ID_COLUMNS: &[&str] = &[
    "connection_id",
    "fact_id",
    "timestamp",
    "advertised_fact_id",
];
pub const SYNC_HAVE_ID_KEY_COLUMNS: &[&str] = &["connection_id", "fact_id"];
pub const SYNC_HAVE_ID_TABLE: TypedTableSchema = TypedTableSchema {
    table: SYNC_HAVE_ID_ROWS,
    columns: SYNC_HAVE_ID_COLUMNS,
    key_columns: SYNC_HAVE_ID_KEY_COLUMNS,
};

pub fn sync_have_id_row(row_fact_id: FactId, fact: &fact::SyncHaveIdFact) -> TableInsert {
    SYNC_HAVE_ID_TABLE.insert(vec![
        Value::Bytes(fact.connection_id.to_vec()),
        Value::Bytes(row_fact_id.to_vec()),
        Value::U64(fact.timestamp),
        Value::Bytes(fact.fact_id.to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncHaveIdFact, String> {
    project::decode::decode_fact(bytes)
}

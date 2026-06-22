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
#[cfg(not(verus_keep_ghost))]
pub mod proofs;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_SYNC_NEED_ID: u8 = encode::TYPE_SYNC_NEED_ID;

/// Sync need-id projection rows, keyed by `connection_id || fact_id`; the value
/// stores the requested fact id. Keeping the fact id in the key keeps repeated
/// needs for the same fact id distinct across compare rounds.
pub const SYNC_NEED_ID_ROWS: TableName = TableName::new("sync_need_id_rows");

pub const SYNC_NEED_ID_COLUMNS: &[&str] = &["connection_id", "fact_id", "requested_fact_id"];
pub const SYNC_NEED_ID_KEY_COLUMNS: &[&str] = &["connection_id", "fact_id"];
pub const SYNC_NEED_ID_TABLE: TypedTableSchema = TypedTableSchema {
    table: SYNC_NEED_ID_ROWS,
    columns: SYNC_NEED_ID_COLUMNS,
    key_columns: SYNC_NEED_ID_KEY_COLUMNS,
};

pub fn sync_need_id_row(row_fact_id: FactId, fact: &fact::SyncNeedIdFact) -> TableInsert {
    SYNC_NEED_ID_TABLE.insert(vec![
        Value::Bytes(fact.connection_id.to_vec()),
        Value::Bytes(row_fact_id.to_vec()),
        Value::Bytes(fact.fact_id.to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncNeedIdFact, String> {
    project::decode::decode_fact(bytes)
}

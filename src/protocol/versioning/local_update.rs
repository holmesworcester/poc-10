//! Local protocol update fact family.
//!
//! Update facts are local control-plane facts. Live projection of the current
//! update fact requests the generic rebuild effect, records protocol-visible
//! update history, and advances the schema-declared protocol marker. Replay projection of
//! old update facts is a no-op so past updates remain history without rerunning
//! rebuild.

pub mod api;
pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_VERSIONING_UPDATE: u8 = encode::TYPE_VERSIONING_UPDATE;

pub const PROTOCOL_VERSION_ROWS: TableName = TableName::new("protocol_version_rows");
pub const PROTOCOL_VERSION_COLUMNS: &[&str] =
    &["update_fact_id", "protocol_version", "applied_at_ms"];
pub const PROTOCOL_VERSION_KEY_COLUMNS: &[&str] = &["update_fact_id"];
pub const PROTOCOL_VERSION_TABLE: TypedTableSchema = TypedTableSchema {
    table: PROTOCOL_VERSION_ROWS,
    columns: PROTOCOL_VERSION_COLUMNS,
    key_columns: PROTOCOL_VERSION_KEY_COLUMNS,
};

pub fn protocol_version_row(update_fact_id: FactId, update: &fact::UpdateFact) -> TableInsert {
    PROTOCOL_VERSION_TABLE.insert(vec![
        Value::Bytes(update_fact_id.to_vec()),
        Value::U64(u64::from(update.protocol_version)),
        Value::U64(update.applied_at_ms),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UpdateFact, String> {
    encode::decode_update_fact(bytes)
}

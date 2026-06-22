//! Workspace admin grant fact family.
//!
//! Admin facts establish authority to manage a workspace. They are signed,
//! projected only after signer/workspace context is proven, and then exposed as
//! context that other auth and content projectors consume. Keep admin
//! authorization in this module; downstream modules should ask for admin
//! context rather than rechecking grant history.

pub mod api;
pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
#[cfg(not(verus_keep_ghost))]
pub mod proofs;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_ADMIN: u8 = encode::TYPE_ADMIN;

/// Admin grant projection rows, keyed by `workspace_id || admin_id` so the same
/// admin fact id in another workspace cannot collide.
pub const ADMIN_ROWS: TableName = TableName::new("admin_rows");

pub const ADMIN_COLUMNS: &[&str] = &[
    "workspace_id",
    "admin_id",
    "created_at_ms",
    "public_key",
    "authority_fact_id",
    "user_fact_id",
];
pub const ADMIN_KEY_COLUMNS: &[&str] = &["workspace_id", "admin_id"];
pub const ADMIN_TABLE: TypedTableSchema = TypedTableSchema {
    table: ADMIN_ROWS,
    columns: ADMIN_COLUMNS,
    key_columns: ADMIN_KEY_COLUMNS,
};

pub(crate) fn admin_insert(admin_id: FactId, fact: &fact::AdminFact) -> TableInsert {
    ADMIN_TABLE.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(admin_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.public_key.to_vec()),
        Value::Bytes(fact.authority_fact_id.to_vec()),
        Value::Bytes(fact.user_fact_id.to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::AdminFact, String> {
    project::decode::decode_fact(bytes)
}

pub fn encode_fact_payload(fact: &fact::AdminFact) -> Result<Vec<u8>, String> {
    encode::encode_fact(fact)
}

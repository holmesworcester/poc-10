//! User identity fact family.
//!
//! User facts establish named users inside a workspace. They are signed,
//! projected after workspace/admin context is available, and published as user
//! rows/context for content authorship, invites, and query display. Keep user
//! naming and admission policy here; endpoint/device facts represent concrete
//! devices for a user.

pub mod api;
pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_USER: u8 = encode::TYPE_USER;

/// User projection rows, keyed by `workspace_id || user_id`. The user id is the
/// fact id of the user fact being projected.
pub const USER_ROWS: TableName = TableName::new("user_rows");

pub const USER_COLUMNS: &[&str] = &[
    "workspace_id",
    "user_id",
    "created_at_ms",
    "public_key",
    "user_invite_id",
    "username",
];
pub const USER_KEY_COLUMNS: &[&str] = &["workspace_id", "user_id"];
pub const USER_TABLE: TypedTableSchema = TypedTableSchema {
    table: USER_ROWS,
    columns: USER_COLUMNS,
    key_columns: USER_KEY_COLUMNS,
};

/// Row key for a user: `workspace_id || user_id`, matching the schema key fields.
pub fn user_key(workspace_id: &FactId, user_id: &FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(user_id);
    key
}

pub fn user_row(user_id: FactId, user_invite_id: [u8; 32], fact: &fact::UserFact) -> TableInsert {
    USER_TABLE.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(user_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.public_key.to_vec()),
        Value::Bytes(user_invite_id.to_vec()),
        Value::Bytes(fact.username.padded_bytes().to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserFact, String> {
    project::decode::decode_fact(bytes)
}

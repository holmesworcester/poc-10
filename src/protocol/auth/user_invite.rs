//! User invite fact family.
//!
//! User invites authorize a new user to join a workspace. Projection validates
//! signature-evidenced inviter authority and publishes invite context used by acceptance
//! flows. This module owns user-invite bytes and admission; device invites and
//! accepted membership are separate fact families.

pub mod api;
pub mod author;
pub mod encode;
pub mod fact;
pub mod project;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_USER_INVITE: u8 = encode::TYPE_USER_INVITE;

/// User invite projection rows, keyed by `workspace_id || user_invite_id`. The
/// user-invite id is the fact id of the user-invite fact being projected.
pub const USER_INVITE_ROWS: TableName = TableName::new("user_invite_rows");

pub const USER_INVITE_COLUMNS: &[&str] = &[
    "workspace_id",
    "user_invite_id",
    "created_at_ms",
    "public_key",
    "authority_fact_id",
];
pub const USER_INVITE_KEY_COLUMNS: &[&str] = &["workspace_id", "user_invite_id"];
pub const USER_INVITE_TABLE: TypedTableSchema = TypedTableSchema {
    table: USER_INVITE_ROWS,
    columns: USER_INVITE_COLUMNS,
    key_columns: USER_INVITE_KEY_COLUMNS,
};

pub fn user_invite_row(user_invite_id: FactId, fact: &fact::UserInviteFact) -> TableInsert {
    USER_INVITE_TABLE.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(user_invite_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.public_key.to_vec()),
        Value::Bytes(fact.authority_fact_id.to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserInviteFact, String> {
    project::decode::decode_fact(bytes)
}

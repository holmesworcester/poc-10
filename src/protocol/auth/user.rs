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

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

use fact::USERNAME_BYTES;

pub const TYPE_USER: u8 = encode::TYPE_USER;

/// User projection rows, keyed by `workspace_id || user_id`. The user id is the
/// fact id of the user fact being projected.
pub const USER_ROWS: TableName = TableName::new("user_rows");

const USER_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("workspace_id"),
    RowField::bytes32("user_id"),
];
const USER_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("created_at_ms"),
    RowField::bytes32("public_key"),
    RowField::bytes32("user_invite_id"),
    RowField::bytes("username", USERNAME_BYTES),
];

pub const USER_ROW_SCHEMA: RowTableSchema =
    RowTableSchema::new(USER_ROWS, USER_ROW_KEY_FIELDS, USER_ROW_VALUE_FIELDS);

/// Row key for a user: `workspace_id || user_id`, matching the schema key fields.
pub fn user_key(workspace_id: &FactId, user_id: &FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(user_id);
    key
}

pub fn user_row(
    user_id: FactId,
    user_invite_id: [u8; 32],
    fact: &fact::UserFact,
) -> Result<TableRow, String> {
    USER_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.workspace_id.to_vec()),
            RowValue::Bytes(user_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.created_at_ms),
            RowValue::Bytes(fact.public_key.to_vec()),
            RowValue::Bytes(user_invite_id.to_vec()),
            RowValue::Bytes(fact.username.padded_bytes().to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserFact, String> {
    project::decode::decode_fact(bytes)
}

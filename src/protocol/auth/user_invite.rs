//! User invite fact family.
//!
//! User invites authorize a new user to join a workspace. Projection validates
//! signature-evidenced inviter authority and publishes invite context used by acceptance
//! flows. This module owns user-invite bytes and admission; device invites and
//! accepted membership are separate fact families.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub const TYPE_USER_INVITE: u8 = encode::TYPE_USER_INVITE;

/// User invite projection rows, keyed by `workspace_id || user_invite_id`. The
/// user-invite id is the fact id of the user-invite fact being projected.
pub const USER_INVITE_ROWS: TableName = TableName::new("user_invite_rows");

const USER_INVITE_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("workspace_id"),
    RowField::bytes32("user_invite_id"),
];
const USER_INVITE_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("created_at_ms"),
    RowField::bytes32("public_key"),
    RowField::bytes32("authority_fact_id"),
];

pub const USER_INVITE_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    USER_INVITE_ROWS,
    USER_INVITE_ROW_KEY_FIELDS,
    USER_INVITE_ROW_VALUE_FIELDS,
);

pub fn user_invite_row(
    user_invite_id: FactId,
    fact: &fact::UserInviteFact,
) -> Result<TableRow, String> {
    USER_INVITE_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.workspace_id.to_vec()),
            RowValue::Bytes(user_invite_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.created_at_ms),
            RowValue::Bytes(fact.public_key.to_vec()),
            RowValue::Bytes(fact.authority_fact_id.to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserInviteFact, String> {
    decode::decode_fact(bytes)
}

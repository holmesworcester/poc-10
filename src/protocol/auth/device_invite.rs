//! Device invite fact family.
//!
//! Device invites let an existing identity authorize another endpoint. The fact
//! is signed, projection verifies the inviter authority, and rows/context expose
//! the invite key for acceptance flows. This module owns device-invite layout
//! and admission; accepting the invite is handled by `invite_accepted`.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub const TYPE_DEVICE_INVITE: u8 = encode::TYPE_DEVICE_INVITE;

/// Device invite projection rows, keyed by `workspace_id || device_invite_id`.
/// The device-invite id is the fact id of the device-invite fact being
/// projected.
pub const DEVICE_INVITE_ROWS: TableName = TableName::new("device_invite_rows");

const DEVICE_INVITE_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("workspace_id"),
    RowField::bytes32("device_invite_id"),
];
const DEVICE_INVITE_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("created_at_ms"),
    RowField::bytes32("user_authority_fact_id"),
    RowField::bytes32("user_invite_fact_id"),
    RowField::bytes32("public_key"),
];

pub const DEVICE_INVITE_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    DEVICE_INVITE_ROWS,
    DEVICE_INVITE_ROW_KEY_FIELDS,
    DEVICE_INVITE_ROW_VALUE_FIELDS,
);

pub fn device_invite_row(
    device_invite_id: FactId,
    fact: &fact::DeviceInviteFact,
) -> Result<TableRow, String> {
    DEVICE_INVITE_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.workspace_id.to_vec()),
            RowValue::Bytes(device_invite_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.created_at_ms),
            RowValue::Bytes(fact.user_authority_fact_id.to_vec()),
            RowValue::Bytes(fact.user_invite_fact_id.unwrap_or([0; 32]).to_vec()),
            RowValue::Bytes(fact.public_key.to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::DeviceInviteFact, String> {
    project::decode::decode_fact(bytes)
}

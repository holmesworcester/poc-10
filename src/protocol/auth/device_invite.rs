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

use crate::core::facts::FactId;
use crate::core::store::{TableInsert, TableName, TypedTableSchema, Value};

pub const TYPE_DEVICE_INVITE: u8 = encode::TYPE_DEVICE_INVITE;

/// Device invite projection rows, keyed by `workspace_id || device_invite_id`.
/// The device-invite id is the fact id of the device-invite fact being
/// projected.
pub const DEVICE_INVITE_ROWS: TableName = TableName::new("device_invite_rows");

pub const DEVICE_INVITE_COLUMNS: &[&str] = &[
    "workspace_id",
    "device_invite_id",
    "created_at_ms",
    "user_authority_fact_id",
    "user_invite_fact_id",
    "public_key",
];
pub const DEVICE_INVITE_KEY_COLUMNS: &[&str] = &["workspace_id", "device_invite_id"];
pub const DEVICE_INVITE_TABLE: TypedTableSchema = TypedTableSchema {
    table: DEVICE_INVITE_ROWS,
    columns: DEVICE_INVITE_COLUMNS,
    key_columns: DEVICE_INVITE_KEY_COLUMNS,
};

pub fn device_invite_row(device_invite_id: FactId, fact: &fact::DeviceInviteFact) -> TableInsert {
    DEVICE_INVITE_TABLE.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(device_invite_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.user_authority_fact_id.to_vec()),
        Value::Bytes(fact.user_invite_fact_id.unwrap_or([0; 32]).to_vec()),
        Value::Bytes(fact.public_key.to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::DeviceInviteFact, String> {
    project::decode::decode_fact(bytes)
}

//! Workspace admin grant fact family.
//!
//! Admin facts establish authority to manage a workspace. They are signed,
//! projected only after signer/workspace context is proven, and then exposed as
//! context that other auth and content projectors consume. Keep admin
//! authorization in this module; downstream modules should ask for admin
//! context rather than rechecking grant history.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod cli;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub(crate) use decode::Codec;

pub const TYPE_ADMIN: u8 = encode::TYPE_ADMIN;

/// Admin grant projection rows, keyed by `workspace_id || admin_id` so the same
/// admin fact id in another workspace cannot collide.
pub const ADMIN_ROWS: TableName = TableName::new("admin_rows");

const ADMIN_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("workspace_id"),
    RowField::bytes32("admin_id"),
];
const ADMIN_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("created_at_ms"),
    RowField::bytes32("public_key"),
    RowField::bytes32("authority_fact_id"),
    RowField::bytes32("user_fact_id"),
];

pub const ADMIN_ROW_SCHEMA: RowTableSchema =
    RowTableSchema::new(ADMIN_ROWS, ADMIN_ROW_KEY_FIELDS, ADMIN_ROW_VALUE_FIELDS);

pub(crate) fn admin_row(admin_id: FactId, fact: &fact::AdminFact) -> Result<TableRow, String> {
    ADMIN_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.workspace_id.to_vec()),
            RowValue::Bytes(admin_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.created_at_ms),
            RowValue::Bytes(fact.public_key.to_vec()),
            RowValue::Bytes(fact.authority_fact_id.to_vec()),
            RowValue::Bytes(fact.user_fact_id.to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::AdminFact, String> {
    decode::decode_fact(bytes)
}

pub fn encode_fact_payload(fact: &fact::AdminFact) -> Result<Vec<u8>, String> {
    encode::encode_fact(fact)
}

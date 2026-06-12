//! Invite-server fact family.
//!
//! Invite-server facts advertise a server endpoint that can help bootstrap
//! connection requests. They are signed, projected through auth authority
//! context, and exposed as invite-server rows plus context for connection
//! handshakes. Keep server advertisement policy here, not in network send handlers.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub const TYPE_INVITE_SERVER: u8 = encode::TYPE_INVITE_SERVER;

/// Invite-server projection rows, keyed by `workspace_id || invite_server_id`.
/// The invite-server id is the fact id of the invite-server fact being
/// projected.
pub const INVITE_SERVER_ROWS: TableName = TableName::new("invite_server_rows");

pub type InviteServerId = FactId;

const INVITE_SERVER_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("workspace_id"),
    RowField::bytes32("invite_server_id"),
];
const INVITE_SERVER_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("created_at_ms"),
    RowField::bytes32("public_key"),
    RowField::bytes32("authority_fact_id"),
];

pub const INVITE_SERVER_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    INVITE_SERVER_ROWS,
    INVITE_SERVER_ROW_KEY_FIELDS,
    INVITE_SERVER_ROW_VALUE_FIELDS,
);

pub fn invite_server_row(
    invite_server_id: InviteServerId,
    fact: &fact::InviteServerFact,
) -> Result<TableRow, String> {
    INVITE_SERVER_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.workspace_id.to_vec()),
            RowValue::Bytes(invite_server_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.created_at_ms),
            RowValue::Bytes(fact.public_key.to_vec()),
            RowValue::Bytes(fact.authority_fact_id.to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteServerFact, String> {
    decode::decode_fact(bytes)
}

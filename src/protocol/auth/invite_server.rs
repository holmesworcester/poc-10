//! Invite-server fact family.
//!
//! Invite-server facts advertise a server endpoint that can help bootstrap
//! connection requests. They are signed, projected through auth authority
//! context, and exposed as invite-server rows plus context for connection
//! handshakes. Keep server advertisement policy here, not in network send handlers.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_INVITE_SERVER: u8 = encode::TYPE_INVITE_SERVER;

/// Invite-server projection rows, keyed by `workspace_id || invite_server_id`.
/// The invite-server id is the fact id of the invite-server fact being
/// projected.
pub const INVITE_SERVER_ROWS: TableName = TableName::new("invite_server_rows");

pub type InviteServerId = FactId;

pub const INVITE_SERVER_COLUMNS: &[&str] = &[
    "workspace_id",
    "invite_server_id",
    "created_at_ms",
    "public_key",
    "authority_fact_id",
];
pub const INVITE_SERVER_KEY_COLUMNS: &[&str] = &["workspace_id", "invite_server_id"];
pub const INVITE_SERVER_TABLE: TypedTableSchema = TypedTableSchema {
    table: INVITE_SERVER_ROWS,
    columns: INVITE_SERVER_COLUMNS,
    key_columns: INVITE_SERVER_KEY_COLUMNS,
};

pub fn invite_server_row(
    invite_server_id: InviteServerId,
    fact: &fact::InviteServerFact,
) -> TableInsert {
    INVITE_SERVER_TABLE.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(invite_server_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.public_key.to_vec()),
        Value::Bytes(fact.authority_fact_id.to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteServerFact, String> {
    project::decode::decode_fact(bytes)
}

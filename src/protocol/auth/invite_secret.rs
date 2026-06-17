//! Invite secret fact family.
//!
//! Invite secrets are local or scoped capabilities used to bootstrap users,
//! devices, and invite servers. Projection publishes invite context consumed by
//! connection requests and acceptance flows. Keep secret layout and invite
//! command helpers here; accepted membership facts live in `invite_accepted`.

pub mod api;
pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;

use crate::core::store::{TableInsert, TableName, TypedTableSchema, Value};

/// Invite-secret projection rows, keyed by
/// `bootstrap_hash || workspace_id_or_zero || invite_fact_id_or_zero`. A
/// connection bootstrap proves knowledge of the bootstrap secret by presenting
/// the matching hash; the scoped key lets the same local secret back separate
/// workspace/invite acceptances without row conflicts.
pub const INVITE_SECRET_ROWS: TableName = TableName::new("invite_secret_rows");

pub const INVITE_SECRET_COLUMNS: &[&str] = &[
    "bootstrap_hash",
    "workspace_id_or_zero",
    "invite_fact_id_or_zero",
    "bootstrap_secret",
];
pub const INVITE_SECRET_KEY_COLUMNS: &[&str] = &[
    "bootstrap_hash",
    "workspace_id_or_zero",
    "invite_fact_id_or_zero",
];
pub const INVITE_SECRET_TABLE: TypedTableSchema = TypedTableSchema {
    table: INVITE_SECRET_ROWS,
    columns: INVITE_SECRET_COLUMNS,
    key_columns: INVITE_SECRET_KEY_COLUMNS,
};

pub fn invite_secret_row(fact: &fact::InviteSecretFact) -> TableInsert {
    INVITE_SECRET_TABLE.insert(vec![
        Value::Bytes(fact.bootstrap_hash.to_vec()),
        Value::Bytes(fact.workspace_id.unwrap_or([0; 32]).to_vec()),
        Value::Bytes(fact.invite_fact_id.unwrap_or([0; 32]).to_vec()),
        Value::Bytes(fact.bootstrap_secret.to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteSecretFact, String> {
    project::decode::decode_fact(bytes)
}

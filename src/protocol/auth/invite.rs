//! Invite secret fact family.
//!
//! Invite secrets are local or scoped capabilities used to bootstrap users,
//! devices, and invite servers. Projection publishes invite context consumed by
//! connection requests and acceptance flows. Keep secret layout and invite
//! command helpers here; accepted membership facts live in `invite_accepted`.

pub mod adapt;
pub mod authenticate;
pub mod cli;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub(crate) use decode::Codec;

/// Invite-secret projection rows, keyed by `bootstrap_hash`. A connection
/// bootstrap proves knowledge of the bootstrap secret by presenting the
/// matching hash; this projector stores the private value beside the hash so
/// the bootstrap path can look it up locally without exposing the private value
/// in the fact.
pub const INVITE_SECRET_ROWS: TableName = TableName::new("invite_secret_rows");

const INVITE_SECRET_ROW_KEY_FIELDS: &[RowField] = &[RowField::bytes32("bootstrap_hash")];
const INVITE_SECRET_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::bytes32("bootstrap_secret"),
    RowField::bytes32("workspace_id_or_zero"),
    RowField::bytes32("invite_fact_id_or_zero"),
];

pub const INVITE_SECRET_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    INVITE_SECRET_ROWS,
    INVITE_SECRET_ROW_KEY_FIELDS,
    INVITE_SECRET_ROW_VALUE_FIELDS,
);

pub fn invite_secret_row(fact: &fact::InviteSecretFact) -> Result<TableRow, String> {
    INVITE_SECRET_ROW_SCHEMA.row(
        &[RowValue::Bytes(fact.bootstrap_hash.to_vec())],
        &[
            RowValue::Bytes(fact.bootstrap_secret.to_vec()),
            RowValue::Bytes(fact.workspace_id.unwrap_or([0; 32]).to_vec()),
            RowValue::Bytes(fact.invite_fact_id.unwrap_or([0; 32]).to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteSecretFact, String> {
    decode::decode_fact(bytes)
}

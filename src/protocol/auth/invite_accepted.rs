//! Invite acceptance fact family.
//!
//! Invite-accepted facts turn an invite secret into concrete workspace/user or
//! endpoint membership. Projection validates the invite context and materializes
//! the accepted identity rows/context that later projectors rely on. Commands
//! here create the local facts needed to accept an invite; invite creation stays
//! in `auth::invite`.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub(crate) use decode::Codec;

pub const TYPE_INVITE_ACCEPTED: u8 = encode::TYPE_INVITE_ACCEPTED;

/// Invite-accepted projection rows, keyed by
/// `accepted_endpoint_id || workspace_id || invite_fact_id`.
pub const INVITE_ACCEPTED_ROWS: TableName = TableName::new("invite_accepted_rows");

const INVITE_ACCEPTED_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("accepted_endpoint_id"),
    RowField::bytes32("workspace_id"),
    RowField::bytes32("invite_fact_id"),
];
const INVITE_ACCEPTED_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::bytes32("invite_accepted_fact_id"),
    RowField::bytes32("invite_secret_fact_id"),
    RowField::bytes32("bootstrap_hash"),
];

pub const INVITE_ACCEPTED_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    INVITE_ACCEPTED_ROWS,
    INVITE_ACCEPTED_ROW_KEY_FIELDS,
    INVITE_ACCEPTED_ROW_VALUE_FIELDS,
);

pub fn invite_accepted_row(
    invite_accepted_fact_id: [u8; 32],
    fact: &fact::InviteAcceptedFact,
) -> Result<TableRow, String> {
    INVITE_ACCEPTED_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.accepted_endpoint_id.to_vec()),
            RowValue::Bytes(fact.workspace_id.to_vec()),
            RowValue::Bytes(fact.invite_fact_id.to_vec()),
        ],
        &[
            RowValue::Bytes(invite_accepted_fact_id.to_vec()),
            RowValue::Bytes(fact.invite_secret_fact_id.to_vec()),
            RowValue::Bytes(fact.bootstrap_hash.to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteAcceptedFact, String> {
    decode::decode_fact(bytes)
}

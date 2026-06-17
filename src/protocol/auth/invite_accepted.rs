//! Invite acceptance fact family.
//!
//! Invite-accepted facts turn an invite secret into concrete workspace/user or
//! endpoint membership. Projection validates the invite context and materializes
//! the accepted identity rows/context that later projectors rely on. Commands
//! here create the local facts needed to accept an invite; invite creation stays
//! in `auth::invite`.

pub mod api;
pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};
use crate::protocol::auth::invite_secret::fact::InviteSecretFact;
use crate::protocol::connection::request::encode::{encode_optional_addr, ADDR_BLOCK_BYTES};

pub const TYPE_INVITE_ACCEPTED: u8 = encode::TYPE_INVITE_ACCEPTED;
pub const AUTH_WORKSPACE_ACCEPTED_ROLE: &str = "auth_workspace_accepted";

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
    RowField::bytes32("bootstrap_hash"),
    RowField::bytes32("bootstrap_secret"),
    RowField::bytes32("bootstrap_endpoint_id"),
    RowField::bytes("bootstrap_addr", ADDR_BLOCK_BYTES),
    RowField::bytes32("user_authority_fact_id_or_zero"),
    RowField::u8("endpoint_role"),
    RowField::u8("identity_scope"),
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
            RowValue::Bytes(fact.bootstrap_hash.to_vec()),
            RowValue::Bytes(fact.bootstrap_secret.to_vec()),
            RowValue::Bytes(fact.bootstrap_endpoint_id.to_vec()),
            RowValue::Bytes(encode_optional_addr(Some(fact.bootstrap_addr))?.to_vec()),
            RowValue::Bytes(fact.user_authority_fact_id.unwrap_or([0; 32]).to_vec()),
            RowValue::U8(fact.endpoint_role.as_u8()),
            RowValue::U8(u8::from(fact.identity_scope)),
        ],
    )
}

pub fn derived_invite_secret(fact: &fact::InviteAcceptedFact) -> InviteSecretFact {
    if fact.identity_scope {
        InviteSecretFact::scoped(
            fact.bootstrap_secret,
            fact.workspace_id,
            fact.invite_fact_id,
        )
    } else {
        InviteSecretFact::new(fact.bootstrap_secret)
    }
}

pub fn derived_invite_secret_fact_id(fact: &fact::InviteAcceptedFact) -> Result<FactId, String> {
    let secret = derived_invite_secret(fact);
    let bytes = crate::protocol::auth::invite_secret::encode::encode_fact(&secret)?;
    Ok(Fact::new(FactScope::Local, 0, bytes).id)
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteAcceptedFact, String> {
    project::decode::decode_fact(bytes)
}

pub fn workspace_accepted_need(
    owner: crate::core::facts::FactId,
    workspace_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        AUTH_WORKSPACE_ACCEPTED_ROLE,
        crate::core::facts::FactScope::Global,
        workspace_id,
        workspace_id,
    )
}

pub fn workspace_accepted_offer(
    owner: crate::core::facts::FactId,
    workspace_id: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        AUTH_WORKSPACE_ACCEPTED_ROLE,
        crate::core::facts::FactScope::Global,
        workspace_id,
        workspace_id,
    )
}

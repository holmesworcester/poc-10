//! Shared endpoint identity fact family.
//!
//! Endpoint-shared facts are the signed, shareable proof that an endpoint name,
//! role, and public signing key belong in a workspace. Projection validates the
//! signature and workspace/user context, then publishes endpoint rows and
//! signer context that content, admin, connection, and auth projectors
//! rely on.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod cli;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

pub const TYPE_ENDPOINT_SHARED: u8 = encode::TYPE_ENDPOINT_SHARED;

/// Shared endpoint identity projection rows, keyed by
/// `workspace_id || endpoint_shared_id`. The endpoint shared id is the fact id
/// of the projected endpoint-shared fact.
pub const ENDPOINT_SHARED_ROWS: TableName = TableName::new("auth_endpoint_shared_rows");

const ENDPOINT_SHARED_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("workspace_id"),
    RowField::bytes32("endpoint_shared_id"),
];
const ENDPOINT_SHARED_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("created_at_ms"),
    RowField::bytes32("endpoint_id"),
    RowField::bytes32("signing_public_key"),
    RowField::u8("endpoint_role"),
    RowField::bytes32("user_authority_fact_id"),
    RowField::bytes("device_name", fact::ENDPOINT_DEVICE_NAME_BYTES),
];

pub const ENDPOINT_SHARED_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    ENDPOINT_SHARED_ROWS,
    ENDPOINT_SHARED_ROW_KEY_FIELDS,
    ENDPOINT_SHARED_ROW_VALUE_FIELDS,
);

pub fn endpoint_shared_row(
    endpoint_shared_id: FactId,
    fact: &fact::EndpointSharedFact,
) -> Result<TableRow, String> {
    ENDPOINT_SHARED_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.workspace_id.to_vec()),
            RowValue::Bytes(endpoint_shared_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.created_at_ms),
            RowValue::Bytes(fact.endpoint_id.to_vec()),
            RowValue::Bytes(fact.signing_public_key.to_vec()),
            RowValue::U8(fact.endpoint_role.as_u8()),
            RowValue::Bytes(fact.user_authority_fact_id.to_vec()),
            RowValue::Bytes(fact.device_name.padded_bytes().to_vec()),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EndpointSharedFact, String> {
    decode::decode_fact(bytes)
}

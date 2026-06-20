//! Shared endpoint identity fact family.
//!
//! Endpoint-shared facts are the signed, shareable proof that an endpoint name,
//! role, and public signing key belong in a workspace. Projection validates the
//! signature and workspace/user context, then publishes endpoint rows and
//! signer context that content, admin, connection, and auth projectors
//! rely on.

pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_ENDPOINT_SHARED: u8 = encode::TYPE_ENDPOINT_SHARED;

/// Shared endpoint identity projection rows, keyed by
/// `workspace_id || endpoint_shared_id`. The endpoint shared id is the fact id
/// of the projected endpoint-shared fact.
pub const ENDPOINT_SHARED_ROWS: TableName = TableName::new("auth_endpoint_shared_rows");

pub const ENDPOINT_SHARED_COLUMNS: &[&str] = &[
    "workspace_id",
    "endpoint_shared_id",
    "created_at_ms",
    "endpoint_id",
    "signing_public_key",
    "endpoint_role",
    "user_authority_fact_id",
    "device_name",
];
pub const ENDPOINT_SHARED_KEY_COLUMNS: &[&str] = &["workspace_id", "endpoint_shared_id"];
pub const ENDPOINT_SHARED_TABLE: TypedTableSchema = TypedTableSchema {
    table: ENDPOINT_SHARED_ROWS,
    columns: ENDPOINT_SHARED_COLUMNS,
    key_columns: ENDPOINT_SHARED_KEY_COLUMNS,
};

pub fn endpoint_shared_row(
    endpoint_shared_id: FactId,
    fact: &fact::EndpointSharedFact,
) -> TableInsert {
    ENDPOINT_SHARED_TABLE.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(endpoint_shared_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.endpoint_id.to_vec()),
        Value::Bytes(fact.signing_public_key.to_vec()),
        Value::U64(u64::from(fact.endpoint_role.as_u8())),
        Value::Bytes(fact.user_authority_fact_id.to_vec()),
        Value::Bytes(fact.device_name.padded_bytes().to_vec()),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EndpointSharedFact, String> {
    project::decode::decode_fact(bytes)
}

//! Local endpoint fact family.
//!
//! Endpoint facts describe this store's local identity material: endpoint id,
//! signing keys, and local secret rows used by command capabilities and
//! projection context. These facts are local authority, not shared identity
//! proofs. Shared endpoint visibility lives in `endpoint_shared`.

pub mod api;
pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod proofs;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};

pub const TYPE_LOCAL_ENDPOINT: u8 = encode::TYPE_LOCAL_ENDPOINT;

pub use project::{daemon_endpoint_need, daemon_endpoint_offer};

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EndpointFact, String> {
    project::decode::decode_fact(bytes)
}

// ---------------------------------------------------------------------------
// Local endpoint projection rows.
//
// State is module-owned and keyed under the stable `b"local"` key. The row
// carries private material, so private reads stay behind `author::local_endpoint`
// while `queries.rs` exposes only public endpoint identity.
// ---------------------------------------------------------------------------

pub const LOCAL_ENDPOINT_ROWS: TableName = TableName::new("local_endpoint_rows");

pub const LOCAL_KEY: &[u8] = b"local";

pub const LOCAL_ENDPOINT_COLUMNS: &[&str] = &[
    "local_key",
    "endpoint_id",
    "secret",
    "signing_public_key",
    "signing_secret",
];
pub const LOCAL_ENDPOINT_KEY_COLUMNS: &[&str] = &["local_key"];
pub const LOCAL_ENDPOINT_TABLE: TypedTableSchema = TypedTableSchema {
    table: LOCAL_ENDPOINT_ROWS,
    columns: LOCAL_ENDPOINT_COLUMNS,
    key_columns: LOCAL_ENDPOINT_KEY_COLUMNS,
};

pub fn local_endpoint_insert(fact: &fact::EndpointFact) -> TableInsert {
    LOCAL_ENDPOINT_TABLE.insert(vec![
        Value::Bytes(LOCAL_KEY.to_vec()),
        Value::Bytes(fact.endpoint.to_vec()),
        Value::Bytes(fact.secret.to_vec()),
        Value::Bytes(fact.signing_public_key.to_vec()),
        Value::Bytes(fact.signing_secret.to_vec()),
    ])
}

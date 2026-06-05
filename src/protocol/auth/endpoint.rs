//! Local endpoint fact family.
//!
//! Endpoint facts describe this store's local identity material: endpoint id,
//! signing keys, and local secret rows used by command capabilities and
//! projection context. These facts are local authority, not shared identity
//! proofs. Shared endpoint visibility lives in `endpoint_shared`.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::store::{TableName, TableRow};

pub(crate) use decode::Codec;

pub const TYPE_LOCAL_ENDPOINT: u8 = encode::TYPE_LOCAL_ENDPOINT;

pub use project::{daemon_endpoint_need, daemon_endpoint_offer};

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EndpointFact, String> {
    decode::decode_fact(bytes)
}

// ---------------------------------------------------------------------------
// Local endpoint projection rows.
//
// State is module-owned and keyed under the stable `b"local"` key. The
// separation across four tables keeps endpoint id, connection-frame secret,
// signing public key, and signing secret independently addressable by command
// capabilities and tests. The rows carry private material, so this row surface
// stays in the family module rather than the public `queries.rs` read model.
// ---------------------------------------------------------------------------

pub const LOCAL_ENDPOINT_ROWS: TableName = TableName::new("local_endpoint_rows");
pub const LOCAL_ENDPOINT_SECRET_ROWS: TableName = TableName::new("local_endpoint_secret_rows");
pub const LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS: TableName =
    TableName::new("local_endpoint_signing_public_key_rows");
pub const LOCAL_ENDPOINT_SIGNING_SECRET_ROWS: TableName =
    TableName::new("local_endpoint_signing_secret_rows");

pub const LOCAL_KEY: &[u8] = b"local";

pub fn endpoint_rows(fact: &fact::EndpointFact) -> Vec<TableRow> {
    vec![
        TableRow {
            table: LOCAL_ENDPOINT_ROWS,
            key: LOCAL_KEY.to_vec(),
            value: fact.endpoint.to_vec(),
        },
        TableRow {
            table: LOCAL_ENDPOINT_SECRET_ROWS,
            key: LOCAL_KEY.to_vec(),
            value: fact.secret.to_vec(),
        },
        TableRow {
            table: LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
            key: LOCAL_KEY.to_vec(),
            value: fact.signing_public_key.to_vec(),
        },
        TableRow {
            table: LOCAL_ENDPOINT_SIGNING_SECRET_ROWS,
            key: LOCAL_KEY.to_vec(),
            value: fact.signing_secret.to_vec(),
        },
    ]
}

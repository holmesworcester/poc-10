//! Projection row layouts for local endpoint state.
//!
//! State is module-owned and keyed under the stable `b"local"` key. The
//! separation across four tables keeps endpoint id, transport secret, signing
//! public key, and signing secret independently addressable by queries and
//! tests without giving core semantic knowledge of the values.

use crate::core::store::{TableName, TableRow};

use super::fact::EndpointFact;

pub const LOCAL_ENDPOINT_ROWS: TableName = TableName::new("local_endpoint_rows");
pub const LOCAL_ENDPOINT_SECRET_ROWS: TableName = TableName::new("local_endpoint_secret_rows");
pub const LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS: TableName =
    TableName::new("local_endpoint_signing_public_key_rows");
pub const LOCAL_ENDPOINT_SIGNING_SECRET_ROWS: TableName =
    TableName::new("local_endpoint_signing_secret_rows");

pub const LOCAL_KEY: &[u8] = b"local";

pub fn endpoint_rows(fact: &EndpointFact) -> Vec<TableRow> {
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

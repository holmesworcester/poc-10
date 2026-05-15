//! Schema for local endpoint rows.
//!
//! Endpoint state is module-owned local state. Core only creates the declared
//! row tables; this module decides what keys and values mean.

use crate::core::store::{Schema, Store, TableName};

pub const LOCAL_ENDPOINT: TableName = TableName::new("identity.local_endpoint");
pub const LOCAL_ENDPOINT_SECRET: TableName = TableName::new("identity.local_endpoint_secret");
pub const LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY: TableName =
    TableName::new("identity.local_endpoint_signing_public_key");
pub const LOCAL_ENDPOINT_SIGNING_SECRET: TableName =
    TableName::new("identity.local_endpoint_signing_secret");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("identity.local_endpoint.v1", LOCAL_ENDPOINT),
    Schema::durable_row_table("identity.local_endpoint_secret.v1", LOCAL_ENDPOINT_SECRET),
    Schema::durable_row_table(
        "identity.local_endpoint_signing_public_key.v1",
        LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY,
    ),
    Schema::durable_row_table(
        "identity.local_endpoint_signing_secret.v1",
        LOCAL_ENDPOINT_SIGNING_SECRET,
    ),
];

impl super::commands::LocalEndpointRead for Store {
    fn local_endpoint_secret(&self) -> Result<Option<Vec<u8>>, String> {
        self.table_row(LOCAL_ENDPOINT_SECRET, b"local")
            .map_err(|err| format!("load local endpoint secret: {err}"))
    }

    fn local_endpoint(&self) -> Result<Option<Vec<u8>>, String> {
        self.table_row(LOCAL_ENDPOINT, b"local")
            .map_err(|err| format!("load local endpoint: {err}"))
    }

    fn local_endpoint_signing_public_key(&self) -> Result<Option<Vec<u8>>, String> {
        self.table_row(LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY, b"local")
            .map_err(|err| format!("load local endpoint signing public key: {err}"))
    }

    fn local_endpoint_signing_secret(&self) -> Result<Option<Vec<u8>>, String> {
        self.table_row(LOCAL_ENDPOINT_SIGNING_SECRET, b"local")
            .map_err(|err| format!("load local endpoint signing secret: {err}"))
    }
}

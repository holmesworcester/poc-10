//! Schema for local endpoint rows.
//!
//! Endpoint state is module-owned local state. Core only creates the declared
//! row tables; this module decides what keys and values mean.

use crate::core::store::{Schema, TableName};

pub const LOCAL_ENDPOINT: TableName = TableName::new("identity.local_endpoint");
pub const LOCAL_ENDPOINT_SECRET: TableName = TableName::new("identity.local_endpoint_secret");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("identity.local_endpoint.v1", LOCAL_ENDPOINT),
    Schema::durable_row_table("identity.local_endpoint_secret.v1", LOCAL_ENDPOINT_SECRET),
];

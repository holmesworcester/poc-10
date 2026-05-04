//! Schema for local connection route rows.
//!
//! The table is owned by the transport-target event module because only that
//! module knows how to encode and decode route values.

use crate::core::store::{Schema, TableName};

pub const TRANSPORT_TARGETS: TableName = TableName::new("connection.transport_targets");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "connection.transport_targets.v1",
    TRANSPORT_TARGETS,
)];

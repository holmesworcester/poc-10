use crate::core::store::{Schema, TableName};

pub const TRANSPORT_TARGETS: TableName = TableName::new("connection.transport_targets");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "connection.transport_targets.v1",
    TRANSPORT_TARGETS,
)];

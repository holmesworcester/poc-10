use crate::core::store::{Schema, TableName};

pub const TRANSPORT_TARGETS: TableName = TableName::new("connection.transport_targets");

pub const SCHEMAS: &[Schema] = &[Schema::durable(
    "connection.transport_targets.v1",
    r#"
    CREATE TABLE IF NOT EXISTS "connection.transport_targets" (
        row_key BLOB PRIMARY KEY NOT NULL,
        row_value BLOB NOT NULL
    );
    "#,
)];

use crate::core::store::{Schema, TableName};

pub const LOCAL_ENDPOINT: TableName = TableName::new("identity.local_endpoint");
pub const LOCAL_ENDPOINT_SECRET: TableName = TableName::new("identity.local_endpoint_secret");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable(
        "identity.local_endpoint.v1",
        r#"
        CREATE TABLE IF NOT EXISTS "identity.local_endpoint" (
            row_key BLOB PRIMARY KEY NOT NULL,
            row_value BLOB NOT NULL
        );
        "#,
    ),
    Schema::durable(
        "identity.local_endpoint_secret.v1",
        r#"
        CREATE TABLE IF NOT EXISTS "identity.local_endpoint_secret" (
            row_key BLOB PRIMARY KEY NOT NULL,
            row_value BLOB NOT NULL
        );
        "#,
    ),
];

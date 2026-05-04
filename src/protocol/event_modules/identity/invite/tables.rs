use crate::core::store::{Schema, TableName};

pub const INVITE_SECRETS: TableName = TableName::new("identity.invite_secrets");

pub const SCHEMAS: &[Schema] = &[Schema::durable(
    "identity.invite_secrets.v1",
    r#"
    CREATE TABLE IF NOT EXISTS "identity.invite_secrets" (
        row_key BLOB PRIMARY KEY NOT NULL,
        row_value BLOB NOT NULL
    );
    "#,
)];

use crate::core::store::{Schema, TableName};

pub const INVITE_SECRETS: TableName = TableName::new("identity.invite_secrets");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "identity.invite_secrets.v1",
    INVITE_SECRETS,
)];

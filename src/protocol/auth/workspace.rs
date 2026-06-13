//! Workspace fact family.
//!
//! Workspace facts are the root identity object for most protocol state.
//! Projection materializes workspace rows and context that users, endpoints,
//! content, auth key material, and sync all depend on. Commands here create or
//! inspect workspaces; local membership helpers expose this store's
//! capabilities for command queries.

pub mod author;
pub mod cli;
pub mod commands;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

pub const TYPE_WORKSPACE: u8 = encode::TYPE_WORKSPACE;

pub const WORKSPACE_ROWS: crate::core::store::TableName =
    crate::core::store::TableName::new("workspace_rows");

const WORKSPACE_ROW_KEY_FIELDS: &[crate::core::row_schema::RowField] =
    &[crate::core::row_schema::RowField::bytes32("workspace_id")];
const WORKSPACE_ROW_VALUE_FIELDS: &[crate::core::row_schema::RowField] = &[
    crate::core::row_schema::RowField::u64be("created_at_ms"),
    crate::core::row_schema::RowField::bytes32("public_key"),
    crate::core::row_schema::RowField::bytes("name", fact::WORKSPACE_NAME_BYTES),
];

pub const WORKSPACE_ROW_SCHEMA: crate::core::row_schema::RowTableSchema =
    crate::core::row_schema::RowTableSchema::new(
        WORKSPACE_ROWS,
        WORKSPACE_ROW_KEY_FIELDS,
        WORKSPACE_ROW_VALUE_FIELDS,
    );

pub(crate) fn workspace_row(
    workspace_id: crate::core::facts::FactId,
    fact: &fact::WorkspaceFact,
) -> Result<crate::core::store::TableRow, String> {
    WORKSPACE_ROW_SCHEMA.row(
        &[crate::core::row_schema::RowValue::Bytes(
            workspace_id.to_vec(),
        )],
        &[
            crate::core::row_schema::RowValue::U64(fact.created_at_ms),
            crate::core::row_schema::RowValue::Bytes(fact.public_key.to_vec()),
            crate::core::row_schema::RowValue::Bytes(fact.name.padded_bytes().to_vec()),
        ],
    )
}

pub fn scope(workspace_id: crate::core::facts::FactId) -> crate::core::facts::FactScope {
    crate::core::facts::FactScope::Scoped {
        kind: crate::core::facts::ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::WorkspaceFact, String> {
    project::decode::decode_fact(bytes)
}

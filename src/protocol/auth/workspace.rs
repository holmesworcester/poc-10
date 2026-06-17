//! Workspace fact family.
//!
//! Workspace facts are the root identity object for most protocol state.
//! Projection materializes workspace rows and context that users, endpoints,
//! content, auth key material, and sync all depend on. Commands here create or
//! inspect workspaces; local membership helpers expose this store's
//! capabilities for command queries.

pub mod api;
pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::store::{TableInsert, TableName, TypedTableSchema, Value};

pub const TYPE_WORKSPACE: u8 = encode::TYPE_WORKSPACE;

pub const WORKSPACE_ROWS: TableName = TableName::new("workspace_rows");

pub const WORKSPACE_COLUMNS: &[&str] = &["workspace_id", "created_at_ms", "public_key", "name"];
pub const WORKSPACE_KEY_COLUMNS: &[&str] = &["workspace_id"];
pub const WORKSPACE_TABLE: TypedTableSchema = TypedTableSchema {
    table: WORKSPACE_ROWS,
    columns: WORKSPACE_COLUMNS,
    key_columns: WORKSPACE_KEY_COLUMNS,
};

pub(crate) fn workspace_insert(workspace_id: FactId, fact: &fact::WorkspaceFact) -> TableInsert {
    WORKSPACE_TABLE.insert(vec![
        Value::Bytes(workspace_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.public_key.to_vec()),
        Value::Bytes(fact.name.padded_bytes().to_vec()),
    ])
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

//! Projection row layout for workspace state.
//!
//! Workspace rows are the durable lookup table for the root namespace facts.
//! The key is the workspace fact id, and the value reuses the canonical layout
//! fields. Keep this file focused on row shape and decoding; creation and
//! authority live in the workspace fact family.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{WorkspaceFact, WorkspaceId, WorkspacePublicKey};
use super::layout;

pub const WORKSPACE_ROWS: TableName = TableName::new("workspace_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRow {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub public_key: WorkspacePublicKey,
    pub name: String,
}

pub fn workspace_row(workspace_id: FactId, fact: &WorkspaceFact) -> Result<TableRow, String> {
    Ok(TableRow {
        table: WORKSPACE_ROWS,
        key: workspace_id.to_vec(),
        value: layout::encode_value(fact)?,
    })
}

pub fn decode_workspace_row(key: &[u8], value: &[u8]) -> Result<WorkspaceRow, String> {
    if key.len() != 32 {
        return Err("workspace row key must be a workspace id".to_string());
    }
    let fact = layout::decode_value(value)?;
    Ok(WorkspaceRow {
        workspace_id: key.try_into().unwrap(),
        created_at_ms: fact.created_at_ms,
        public_key: fact.public_key,
        name: fact.name,
    })
}

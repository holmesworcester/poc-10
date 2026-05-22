//! Read-only workspace projections.
//!
//! Query helpers are the only workspace module functions that inspect
//! projected row state directly. They never write, construct facts, project,
//! or dispatch intents.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::protocol::identity::workspace::rows;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSummary {
    pub workspace_id: FactId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub name: String,
}

pub fn list_workspaces(store: &Store) -> Result<Vec<WorkspaceSummary>, String> {
    let mut workspaces = Vec::new();
    for (key, value) in store
        .table_rows(rows::WORKSPACE_ROWS)
        .map_err(|err| format!("read workspace rows: {err}"))?
    {
        let row = rows::decode_workspace_row(&key, &value)?;
        workspaces.push(WorkspaceSummary {
            workspace_id: row.workspace_id,
            created_at_ms: row.created_at_ms,
            public_key: row.public_key,
            name: row.name,
        });
    }
    Ok(workspaces)
}

pub fn workspace_by_id(store: &Store, workspace_id: FactId) -> Result<WorkspaceSummary, String> {
    list_workspaces(store)?
        .into_iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| format!("workspace row not found for {}", hex_id(&workspace_id)))
}

pub fn count_workspaces(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(rows::WORKSPACE_ROWS)
        .map_err(|err| format!("count workspace rows: {err}"))
}

fn hex_id(id: &FactId) -> String {
    let mut out = String::with_capacity(64);
    for byte in id {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

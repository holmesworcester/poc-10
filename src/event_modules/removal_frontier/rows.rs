//! Projection row layout for removal frontier state.
//!
//! Rows are keyed by `workspace_id || removal_frontier_id`. The frontier id is
//! the fact id of the removal frontier fact being projected. Key wraps and
//! key-secret facts name the frontier by id, so this key shape lets readers
//! join from either direction.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{RemovalFrontierFact, RemovalFrontierId, WorkspaceId};
use super::layout;

pub const REMOVAL_FRONTIER_ROWS: TableName = TableName::new("removal_frontier_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierRow {
    pub workspace_id: WorkspaceId,
    pub removal_frontier_id: RemovalFrontierId,
    pub created_at_ms: u64,
    pub authority_admin_id: FactId,
    pub removal_fact_ids: Vec<FactId>,
}

pub fn removal_frontier_key(
    workspace_id: &WorkspaceId,
    removal_frontier_id: &RemovalFrontierId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(removal_frontier_id);
    key
}

pub fn removal_frontier_row(
    removal_frontier_id: RemovalFrontierId,
    fact: &RemovalFrontierFact,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: REMOVAL_FRONTIER_ROWS,
        key: removal_frontier_key(&fact.workspace_id, &removal_frontier_id),
        value: layout::encode_row_value(fact)?,
    })
}

pub fn decode_removal_frontier_row(key: &[u8], value: &[u8]) -> Result<RemovalFrontierRow, String> {
    if key.len() != 64 {
        return Err("removal frontier row key must be workspace_id || frontier_id".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut removal_frontier_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    removal_frontier_id.copy_from_slice(&key[32..]);
    let decoded = layout::decode_row_value(value)?;
    Ok(RemovalFrontierRow {
        workspace_id,
        removal_frontier_id,
        created_at_ms: decoded.created_at_ms,
        authority_admin_id: decoded.authority_admin_id,
        removal_fact_ids: decoded.removal_fact_ids,
    })
}

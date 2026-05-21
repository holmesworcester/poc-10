//! Projection row layout for local history node secret state.
//!
//! Rows are keyed by `(workspace_id, removal_frontier_id, range_start,
//! range_width, bit_depth, fact_id_prefix)` so time-tree internals,
//! minute_nodes, trie internals and trie leaves each get a unique row. The
//! value carries the fact id of the node and the node secret material so a
//! single row read can yield the AEAD key for a leaf coordinate.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use super::fact::{
    mask_prefix_to_depth, LocalHistoryNodeSecretFact, LocalHistoryNodeSecretId, RemovalFrontierId,
    WorkspaceId, NODE_SECRET_BYTES,
};
use super::layout;

pub const LOCAL_HISTORY_NODE_SECRET_ROWS: TableName =
    TableName::new("local_history_node_secret_rows");

pub const ROW_KEY_BYTES: usize = 32 + 32 + wire::U64_BYTES + wire::U64_BYTES + wire::U16_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretRow {
    pub workspace_id: WorkspaceId,
    pub removal_frontier_id: RemovalFrontierId,
    pub local_history_node_secret_id: LocalHistoryNodeSecretId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub fact_id_prefix: FactId,
    pub tombstone_node_id: FactId,
    pub node_secret: [u8; NODE_SECRET_BYTES],
}

pub fn local_history_node_secret_key(
    workspace_id: &WorkspaceId,
    removal_frontier_id: &RemovalFrontierId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: FactId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(ROW_KEY_BYTES);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(removal_frontier_id);
    key.extend_from_slice(&range_start.to_be_bytes());
    key.extend_from_slice(&range_width.to_be_bytes());
    key.extend_from_slice(&bit_depth.to_be_bytes());
    key.extend_from_slice(&mask_prefix_to_depth(fact_id_prefix, bit_depth));
    key
}

pub fn local_history_node_secret_row(
    local_history_node_secret_id: LocalHistoryNodeSecretId,
    fact: &LocalHistoryNodeSecretFact,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: LOCAL_HISTORY_NODE_SECRET_ROWS,
        key: local_history_node_secret_key(
            &fact.workspace_id,
            &fact.removal_frontier_id,
            fact.range_start,
            fact.range_width,
            fact.bit_depth,
            fact.fact_id_prefix,
        ),
        value: layout::encode_row_value(&local_history_node_secret_id, fact)?,
    })
}

pub fn decode_local_history_node_secret_row(
    key: &[u8],
    value: &[u8],
) -> Result<LocalHistoryNodeSecretRow, String> {
    if key.len() != ROW_KEY_BYTES {
        return Err("local history node secret row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[0..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);
    let range_start = u64::from_be_bytes(key[64..72].try_into().unwrap());
    let range_width = u64::from_be_bytes(key[72..80].try_into().unwrap());
    let bit_depth = u16::from_be_bytes(key[80..82].try_into().unwrap());
    let mut fact_id_prefix = [0; 32];
    fact_id_prefix.copy_from_slice(&key[82..114]);
    let decoded = layout::decode_row_value(value)?;
    Ok(LocalHistoryNodeSecretRow {
        workspace_id,
        removal_frontier_id,
        local_history_node_secret_id: decoded.local_history_node_secret_id,
        range_start,
        range_width,
        bit_depth,
        fact_id_prefix,
        tombstone_node_id: decoded.tombstone_node_id,
        node_secret: decoded.node_secret,
    })
}

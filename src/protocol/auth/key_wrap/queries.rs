//! Read-only key-wrap projection and status queries.
//!
//! Query helpers are the only key_wrap module functions that inspect projected
//! row state directly. They decode the wrap embedded in the row value and prove
//! that the stored coordinate key matches it. They never write, construct facts,
//! project, or dispatch intents.

use crate::core::facts::FactId;
use crate::core::runtime::Runtime;
use crate::core::store::{Store, DEFAULT_QUERY_LIMIT};
use crate::protocol::content;
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeSet;

use super::encode;
use super::fact::KeyWrapFact;
use super::{project::decode, KEY_WRAP_ROW_SCHEMA};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyWrapQuery {
    pub workspace_id: FactId,
    pub removal_frontier_id: FactId,
    pub recipient_key_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyWrapLookup {
    pub workspace_id: FactId,
    pub removal_frontier_id: FactId,
    pub recipient_key_id: FactId,
    pub key_wrap_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAccessQuery {
    pub workspace_id: FactId,
    pub removal_frontier_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAccessStatus {
    pub workspace_id: FactId,
    pub removal_frontier_id: FactId,
    pub access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStatusReport {
    pub recipient_keys: usize,
    pub local_recipient_keys: usize,
    pub removal_frontiers: Vec<RemovalFrontierAccess>,
    pub key_wraps: usize,
    pub local_key_secrets: usize,
    pub local_history_node_secrets: usize,
    pub local_history_leaves: usize,
    pub local_history_node_tombstones: usize,
    pub message_tombstones: usize,
    pub cover_summary: [u8; 32],
    pub history_leaves: Vec<HistoryLeafRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemovalFrontierAccess {
    pub frontier_id: FactId,
    pub access: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryLeafRow {
    pub node_id: FactId,
    pub frontier_id: FactId,
    pub minute: u64,
    pub fact_id_in_minute: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapRow {
    pub key_wrap_id: FactId,
    pub signer_public_key: [u8; 32],
    pub wrap: KeyWrapFact,
}

fn decode_key_wrap_row(key: &[u8], value: &[u8]) -> Result<KeyWrapRow, String> {
    let value_fields = KEY_WRAP_ROW_SCHEMA.decode_value(value)?;
    if value_fields[0].as_u8("version")? != 1 {
        return Err("invalid key wrap row value".to_string());
    }
    let key_wrap_id = value_fields[1].as_bytes32("key_wrap_id")?;
    let signer_public_key = value_fields[2].as_bytes32("signer_public_key")?;
    let wrap = decode::decode_key_wrap(value_fields[3].as_bytes("wrap")?)?;
    if key != encode::key_wrap_coordinate_key(&wrap)? {
        return Err("key wrap row key does not match value".to_string());
    }
    Ok(KeyWrapRow {
        key_wrap_id,
        signer_public_key,
        wrap,
    })
}

fn latest_local_recipient_key(
    runtime: &Runtime,
    workspace_id: FactId,
) -> Result<Option<FactId>, String> {
    runtime
        .store()
        .conn()
        .query_row(
            "SELECT recipient_key_id
             FROM local_recipient_key_rows
             WHERE workspace_id = ?1
             ORDER BY fact_timestamp DESC, recipient_key_id DESC
             LIMIT 1",
            params![workspace_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| format!("load latest local recipient key: {err}"))
}

pub fn recipient_key_for_rotation(
    runtime: &Runtime,
    workspace_id: FactId,
) -> Result<Option<FactId>, String> {
    latest_local_recipient_key(runtime, workspace_id)
}

pub fn lookup_key_wrap(runtime: &Runtime, query: KeyWrapQuery) -> Result<KeyWrapLookup, String> {
    if recipient_key_is_superseded(runtime, query.workspace_id, query.recipient_key_id)? {
        return Err("recipient key is missing or superseded".to_string());
    }
    let key = encode::frontier_root_key_wrap_coordinate_key(
        query.workspace_id,
        query.removal_frontier_id,
        query.recipient_key_id,
    );
    let value = runtime
        .store()
        .table_row(super::KEY_WRAP_ROWS, &key)
        .map_err(|err| format!("load key wrap row: {err}"))?
        .ok_or_else(|| "key wrap is not available yet".to_string())?;
    let row = decode_key_wrap_row(&key, &value)?;
    Ok(KeyWrapLookup {
        workspace_id: query.workspace_id,
        removal_frontier_id: query.removal_frontier_id,
        recipient_key_id: query.recipient_key_id,
        key_wrap_id: row.key_wrap_id,
    })
}

pub fn key_access(
    runtime: &Runtime,
    query: KeyAccessQuery,
    now_ms: Option<u64>,
) -> Result<KeyAccessStatus, String> {
    let access = local_key_secret_frontier_exists(
        runtime.store(),
        query.workspace_id,
        query.removal_frontier_id,
    )? && !workspace_retired_from_access(runtime, query.workspace_id, now_ms)?;
    Ok(KeyAccessStatus {
        workspace_id: query.workspace_id,
        removal_frontier_id: query.removal_frontier_id,
        access,
    })
}

pub fn local_key_secret_count(runtime: &Runtime) -> usize {
    runtime
        .store()
        .conn()
        .query_row("SELECT COUNT(*) FROM local_key_secret_rows", [], |row| {
            row.get::<_, i64>(0).map(|count| count as usize)
        })
        .expect("local key secret count should load rows")
}

fn local_key_secret_frontier_exists(
    store: &Store,
    workspace_id: FactId,
    frontier_id: FactId,
) -> Result<bool, String> {
    store
        .conn()
        .query_row(
            "SELECT 1
             FROM local_key_secret_rows
             WHERE workspace_id = ?1 AND frontier_id = ?2
             LIMIT 1",
            params![workspace_id, frontier_id],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(|err| format!("load local key secret access row: {err}"))
}

fn local_key_secret_frontiers(store: &Store, workspace_id: FactId) -> Result<Vec<FactId>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT frontier_id
             FROM local_key_secret_rows
             WHERE workspace_id = ?1
             ORDER BY created_at_ms, frontier_id
             LIMIT ?2",
        )
        .map_err(|err| format!("load local key secret frontiers: {err}"))?;
    let rows = stmt
        .query_map(params![workspace_id, DEFAULT_QUERY_LIMIT as i64], |row| {
            row.get::<_, FactId>(0)
        })
        .map_err(|err| format!("load local key secret frontiers: {err}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("decode local key secret frontiers: {err}"))
}

pub fn key_wrap_count(runtime: &Runtime) -> Result<usize, String> {
    runtime
        .store()
        .table_row_count(super::KEY_WRAP_ROWS)
        .map_err(|err| format!("count key wraps: {err}"))
}

fn workspace_key_wrap_count(runtime: &Runtime, workspace_id: FactId) -> Result<usize, String> {
    runtime
        .store()
        .table_rows_with_key_prefix(super::KEY_WRAP_ROWS, &workspace_id, DEFAULT_QUERY_LIMIT)
        .map(|rows| rows.len())
        .map_err(|err| format!("load workspace key wraps: {err}"))
}

pub fn key_status_report(
    runtime: &Runtime,
    workspace_id: FactId,
) -> Result<KeyStatusReport, String> {
    let store = runtime.store();
    let leaves = history_leaf_rows(store, workspace_id)?;
    let message_tombstones =
        content::message::queries::message_tombstone_count(store, workspace_id)?;
    let file_tombstones = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM file_deletion_rows WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0).map(|value| value as usize),
        )
        .map_err(|err| format!("load file deletion rows: {err}"))?;
    let local_key_secret_frontiers = local_key_secret_frontiers(store, workspace_id)?;
    let recipient_keys = recipient_key_count(store, workspace_id)?;
    let local_recipient_keys = local_recipient_key_count(store, workspace_id)?;
    let local_history_node_secrets = local_history_node_secret_count(store, workspace_id)?;
    let local_history_node_tombstones = local_history_node_tombstone_count(store, workspace_id)?;
    let removal_frontiers = removal_frontier_ids(store, workspace_id)?
        .into_iter()
        .map(|frontier_id| RemovalFrontierAccess {
            frontier_id,
            access: local_key_secret_frontiers.contains(&frontier_id),
        })
        .collect::<Vec<_>>();
    let key_wraps = workspace_key_wrap_count(runtime, workspace_id)?;
    let cover_summary = cover_summary(&leaves);

    Ok(KeyStatusReport {
        recipient_keys,
        local_recipient_keys,
        removal_frontiers,
        key_wraps,
        local_key_secrets: local_key_secret_frontiers.len(),
        local_history_node_secrets: local_history_node_secrets + leaves.len(),
        local_history_leaves: leaves.len(),
        local_history_node_tombstones: local_history_node_tombstones
            + message_tombstones
            + file_tombstones,
        message_tombstones,
        cover_summary,
        history_leaves: leaves,
    })
}

fn recipient_key_count(store: &Store, workspace_id: FactId) -> Result<usize, String> {
    store
        .conn()
        .query_row(
            "SELECT COUNT(*)
             FROM recipient_key_rows
             WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0).map(|count| count as usize),
        )
        .map_err(|err| format!("count recipient keys: {err}"))
}

fn local_recipient_key_count(store: &Store, workspace_id: FactId) -> Result<usize, String> {
    store
        .conn()
        .query_row(
            "SELECT COUNT(*)
             FROM local_recipient_key_rows
             WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0).map(|count| count as usize),
        )
        .map_err(|err| format!("count local recipient keys: {err}"))
}

fn local_history_node_secret_count(store: &Store, workspace_id: FactId) -> Result<usize, String> {
    store
        .conn()
        .query_row(
            "SELECT COUNT(*)
             FROM local_history_node_secret_rows
             WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0).map(|count| count as usize),
        )
        .map_err(|err| format!("count local history node secrets: {err}"))
}

fn local_history_node_tombstone_count(
    store: &Store,
    workspace_id: FactId,
) -> Result<usize, String> {
    store
        .conn()
        .query_row(
            "SELECT COUNT(*)
             FROM local_history_node_tombstone_rows t
             JOIN local_history_node_secret_rows n ON n.secret_id = t.secret_id
             WHERE n.workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0).map(|count| count as usize),
        )
        .map_err(|err| format!("count local history node tombstones: {err}"))
}

fn removal_frontier_ids(store: &Store, workspace_id: FactId) -> Result<Vec<FactId>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT frontier_id
             FROM removal_frontier_rows
             WHERE workspace_id = ?1
             ORDER BY created_at_ms, frontier_id
             LIMIT ?2",
        )
        .map_err(|err| format!("load removal frontier rows: {err}"))?;
    let rows = stmt
        .query_map(params![workspace_id, DEFAULT_QUERY_LIMIT as i64], |row| {
            row.get::<_, FactId>(0)
        })
        .map_err(|err| format!("load removal frontier rows: {err}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("decode removal frontier rows: {err}"))
}

fn workspace_retired_from_access(
    runtime: &Runtime,
    workspace_id: FactId,
    now_ms: Option<u64>,
) -> Result<bool, String> {
    if content::message::queries::message_tombstone_count(runtime.store(), workspace_id)? > 0 {
        return Ok(true);
    }
    let live_messages =
        content::message::queries::content_message_rows(runtime.store(), workspace_id)?;
    let horizon_floor = now_ms
        .map(|ms| (ms / 60_000).saturating_sub(30 * 24 * 60))
        .unwrap_or(0);
    if horizon_floor > 0
        && live_messages
            .iter()
            .all(|message| message.minute < horizon_floor)
    {
        return Ok(true);
    }
    Ok(false)
}

fn history_leaf_rows(store: &Store, workspace_id: FactId) -> Result<Vec<HistoryLeafRow>, String> {
    let messages = content::message::queries::content_message_rows(store, workspace_id)?;
    let live_message_ids = messages
        .iter()
        .map(|message| message.message_id)
        .collect::<BTreeSet<_>>();
    let mut leaves = messages
        .into_iter()
        .map(|message| HistoryLeafRow {
            node_id: message.message_id,
            frontier_id: message.frontier_id,
            minute: message.minute,
            fact_id_in_minute: message.message_id,
        })
        .collect::<Vec<_>>();
    for file in content::file::queries::content_file_rows(store, workspace_id)? {
        if !live_message_ids.contains(&file.message_id) {
            continue;
        }
        let parent =
            content::message::queries::content_message_row(store, workspace_id, file.message_id)?
                .ok_or_else(|| "file row parent message is not live".to_string())?;
        leaves.push(HistoryLeafRow {
            node_id: file.file_fact_id,
            frontier_id: parent.frontier_id,
            minute: file.created_at_ms / content::message::fact::UNIX_MINUTE_MS,
            fact_id_in_minute: file.file_fact_id,
        });
    }
    leaves.sort_by_key(|leaf| (leaf.minute, leaf.node_id));
    Ok(leaves)
}

fn cover_summary(leaves: &[HistoryLeafRow]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    for leaf in leaves {
        hash.update(&leaf.node_id);
        hash.update(&leaf.minute.to_be_bytes());
        hash.update(&leaf.fact_id_in_minute);
    }
    *hash.finalize().as_bytes()
}

fn recipient_key_is_superseded(
    runtime: &Runtime,
    workspace_id: FactId,
    recipient_key_id: FactId,
) -> Result<bool, String> {
    let target = runtime
        .store()
        .conn()
        .query_row(
            "SELECT endpoint_id
             FROM recipient_key_rows
            WHERE workspace_id = ?1 AND recipient_key_id = ?2
             LIMIT 1",
            params![workspace_id, recipient_key_id],
            |row| row.get::<_, FactId>(0),
        )
        .optional()
        .map_err(|err| format!("load recipient key row: {err}"))?;
    let target_endpoint = target;
    let Some(endpoint_id) = target_endpoint else {
        return Ok(false);
    };
    runtime
        .store()
        .conn()
        .query_row(
            "SELECT 1
             FROM recipient_key_rows
             WHERE workspace_id = ?1
               AND endpoint_id = ?2
               AND previous_recipient_key_id = ?3
               AND recipient_key_id != ?3
             LIMIT 1",
            params![workspace_id, endpoint_id, recipient_key_id],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(|err| format!("load recipient key supersession row: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::key_wrap::fact::WrappedSecretKind;
    use crate::protocol::auth::key_wrap::key_wrap_row;

    #[test]
    fn accepted_key_wrap_row_round_trips_by_coordinate() {
        let wrap = KeyWrapFact {
            workspace_id: [1; 32],
            created_at_ms: 2,
            signer_endpoint_id: [3; 32],
            frontier_id: [4; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: [5; 32],
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            recipient_key_id: [6; 32],
            sender_wrap_public_key: [7; 32],
            nonce: [8; 24],
            ciphertext: [9; 48],
        };
        let row = KeyWrapRow {
            key_wrap_id: [10; 32],
            signer_public_key: [11; 32],
            wrap,
        };
        let table_row = key_wrap_row(row.clone()).expect("row");

        assert_eq!(table_row.table, super::super::KEY_WRAP_ROWS);
        assert_eq!(
            decode_key_wrap_row(&table_row.key, &table_row.value).expect("decode"),
            row
        );
    }
}

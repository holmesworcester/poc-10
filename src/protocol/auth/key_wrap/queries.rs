//! Read-only key-wrap projection and status queries.
//!
//! Query helpers are the only key_wrap module functions that inspect projected
//! row state directly. They decode the wrap embedded in the row value and prove
//! that the stored coordinate key matches it. They never write, construct facts,
//! project, or dispatch intents.

use crate::core::clock;
use crate::core::facts::FactId;
use crate::core::runtime::Runtime;
use crate::core::store::Store;
use crate::protocol::auth::local_key_secret::project::decode as local_key_secret_layout_decode;
use crate::protocol::auth::local_recipient_key::project::decode as local_recipient_layout_decode;
use crate::protocol::auth::recipient_key::project::decode as recipient_key_layout;
use crate::protocol::auth::removal_frontier::project::decode as removal_frontier_decode;
use crate::protocol::content;
use rusqlite::params;
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
    let mut latest = None;
    for fact in runtime.facts() {
        let Ok(local) = local_recipient_layout_decode::decode_local_recipient_key(fact.body())
        else {
            continue;
        };
        if local.workspace_id != workspace_id {
            continue;
        }
        match latest {
            None => latest = Some((fact.timestamp, local.recipient_key_id)),
            Some((timestamp, id)) if (fact.timestamp, local.recipient_key_id) > (timestamp, id) => {
                latest = Some((fact.timestamp, local.recipient_key_id));
            }
            _ => {}
        }
    }
    Ok(latest.map(|(_, id)| id))
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

pub fn key_access(runtime: &Runtime, query: KeyAccessQuery) -> Result<KeyAccessStatus, String> {
    let access = runtime.facts().any(|fact| {
        local_key_secret_layout_decode::decode_local_key_secret(fact.body())
            .map(|secret| {
                secret.workspace_id == query.workspace_id
                    && secret.frontier_id == query.removal_frontier_id
            })
            .unwrap_or(false)
    }) && !workspace_retired_from_access(runtime, query.workspace_id)?;
    Ok(KeyAccessStatus {
        workspace_id: query.workspace_id,
        removal_frontier_id: query.removal_frontier_id,
        access,
    })
}

pub fn local_key_secret_count(runtime: &Runtime) -> usize {
    runtime
        .facts()
        .filter(|fact| local_key_secret_layout_decode::decode_local_key_secret(fact.body()).is_ok())
        .count()
}

fn local_key_secret_frontiers(runtime: &Runtime, workspace_id: FactId) -> Vec<FactId> {
    runtime
        .facts()
        .filter_map(|fact| {
            local_key_secret_layout_decode::decode_local_key_secret(fact.body()).ok()
        })
        .filter(|secret| secret.workspace_id == workspace_id)
        .map(|secret| secret.frontier_id)
        .collect()
}

pub fn key_wrap_count(runtime: &Runtime) -> Result<usize, String> {
    runtime
        .store()
        .table_rows(super::KEY_WRAP_ROWS)
        .map(|rows| rows.len())
        .map_err(|err| format!("load key wraps: {err}"))
}

fn workspace_key_wrap_count(runtime: &Runtime, workspace_id: FactId) -> Result<usize, String> {
    Ok(runtime
        .store()
        .table_rows(super::KEY_WRAP_ROWS)
        .map_err(|err| format!("load key wraps: {err}"))?
        .into_iter()
        .filter_map(|(key, value)| decode_key_wrap_row(&key, &value).ok())
        .filter(|row| row.wrap.workspace_id == workspace_id)
        .count())
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
    let local_key_secret_frontiers = local_key_secret_frontiers(runtime, workspace_id);
    let recipient_keys = runtime
        .facts()
        .filter_map(|fact| recipient_key_layout::decode_recipient_key(&fact.bytes).ok())
        .filter(|key| key.workspace_id == workspace_id)
        .count();
    let local_recipient_keys = runtime
        .facts()
        .filter_map(|fact| {
            local_recipient_layout_decode::decode_local_recipient_key(&fact.bytes).ok()
        })
        .filter(|key| key.workspace_id == workspace_id)
        .count();
    let removal_frontiers = runtime
        .facts()
        .filter_map(|fact| {
            removal_frontier_decode::decode_removal_frontier(&fact.bytes)
                .ok()
                .map(|frontier| (fact.id, frontier))
        })
        .filter(|(_, frontier)| frontier.workspace_id == workspace_id)
        .map(|(frontier_id, _)| RemovalFrontierAccess {
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
        local_history_node_secrets: leaves.len(),
        local_history_leaves: leaves.len(),
        local_history_node_tombstones: message_tombstones + file_tombstones,
        message_tombstones,
        cover_summary,
        history_leaves: leaves,
    })
}

fn workspace_retired_from_access(runtime: &Runtime, workspace_id: FactId) -> Result<bool, String> {
    if content::message::queries::message_tombstone_count(runtime.store(), workspace_id)? > 0 {
        return Ok(true);
    }
    let live_messages =
        content::message::queries::content_message_rows(runtime.store(), workspace_id)?;
    let horizon_floor = clock::logical_time(runtime.store())?
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
    let mut target_endpoint = None;
    for fact in runtime.facts() {
        if fact.id != recipient_key_id {
            continue;
        }
        let recipient = recipient_key_layout::decode_recipient_key(fact.body())?;
        if recipient.workspace_id == workspace_id {
            target_endpoint = Some(recipient.endpoint_id);
        }
    }
    let Some(endpoint_id) = target_endpoint else {
        return Ok(false);
    };
    for fact in runtime.facts() {
        let Ok(recipient) = recipient_key_layout::decode_recipient_key(fact.body()) else {
            continue;
        };
        if recipient.workspace_id == workspace_id
            && recipient.endpoint_id == endpoint_id
            && recipient.previous_recipient_key_id == recipient_key_id
        {
            return Ok(true);
        }
    }
    Ok(false)
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

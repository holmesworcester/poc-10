//! User-facing auth key-material commands and status assembly.
//!
//! These commands are the local entry points for creating recipient keys,
//! removal frontiers, history nodes, key wraps, and retention chops. They read
//! projected auth state, construct facts or local effects,
//! and return receipts suitable for CLI output.

use crate::core::clock;
use crate::core::command_context::{
    CommandClock, CommandContext, CommandOutput, IdentityVault, LocalEncryptionCapability,
    LocalSigningCapability, WorkspaceId,
};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::core::runtime::Runtime;
use crate::core::store::Store;
use crate::protocol::auth;
use crate::protocol::auth::local_history_node_secret::fact::TIME_TREE_BIT_DEPTH;
use crate::protocol::auth::recipient_key::decode as recipient_key_layout;
use crate::protocol::auth::removal_frontier::decode as removal_frontier_decode;
use crate::protocol::content;
use rusqlite::params;
use std::collections::BTreeSet;

use super::encode;
use crate::protocol::auth::local_history_node_secret::decode as local_history_layout_decode;
use crate::protocol::auth::local_key_secret::decode as local_key_secret_layout_decode;
use crate::protocol::auth::local_recipient_key::decode as local_recipient_layout_decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateRecipientKey {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub previous_recipient_key_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateRecipientKeyReceipt {
    pub local_recipient_key_id: FactId,
    pub recipient_key_id: FactId,
    pub recipient_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateKeyFrontier {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateKeyFrontierReceipt {
    pub workspace_id: FactId,
    pub removal_frontier_id: FactId,
    pub local_key_secret_id: FactId,
    pub local_signer_secret_id: FactId,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateHistoryNode {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub removal_frontier_id: FactId,
    pub source_secret_id: FactId,
    pub range_start: u64,
    pub range_width: u64,
    pub tombstone_node_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateHistoryNodeReceipt {
    pub workspace_id: FactId,
    pub removal_frontier_id: FactId,
    pub local_history_node_secret_id: FactId,
    pub source_secret_id: FactId,
    pub range_start: u64,
    pub range_width: u64,
    pub tombstone_node_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChopNow {
    pub workspace_id: FactId,
    pub floor_minute: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChopNowReceipt {
    pub workspace_id: FactId,
    pub floor_minute: u64,
    pub subtree_tombstones_written: usize,
    pub boundary_descend_tombstones_written: usize,
    pub right_side_siblings_materialized: usize,
    pub purged_secret_bytes: usize,
    pub subsumed_message_tombstones_gcd: usize,
    pub subsumed_leaf_tombstones_gcd: usize,
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

pub fn create_recipient_key(
    ctx: &CommandContext<'_>,
    input: CreateRecipientKey,
) -> Result<CommandOutput<CreateRecipientKeyReceipt>, String> {
    let membership = auth::workspace::queries::local_membership(ctx.store(), input.workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.endpoint_role != auth::endpoint_shared::fact::EndpointRole::Device {
        return Err("local endpoint role cannot receive key wraps".to_string());
    }
    let signing = ctx.local_signing_capability(input.workspace_id)?;
    if signing.signer_id != membership.endpoint_id {
        return Err("local signing capability does not match workspace endpoint".to_string());
    }
    if signing.public_key != membership.signing_public_key {
        return Err("local signing capability public key does not match membership".to_string());
    }
    let recipient_secret = crypto::random_x25519_private_key();
    let recipient_key = crypto::x25519_public_key(&recipient_secret);
    let recipient_fact = auth::recipient_key::author::authored_recipient_key_fact(
        input.workspace_id,
        membership.endpoint_id,
        recipient_key,
        input.previous_recipient_key_id,
        input.created_at_ms,
        signing.public_key,
    )?;
    let recipient_signature = auth::signature::author::sign_fact(
        input.workspace_id,
        &recipient_fact,
        &signing.private_key,
        input.created_at_ms,
    )?;
    let (_local, local_fact) = auth::local_recipient_key::author::recipient_key_fact(
        input.workspace_id,
        recipient_fact.id,
        recipient_key,
        recipient_secret,
        input.created_at_ms,
    )?;
    Ok(CommandOutput::new(CreateRecipientKeyReceipt {
        local_recipient_key_id: local_fact.id,
        recipient_key_id: recipient_fact.id,
        recipient_key,
    })
    .with_facts(vec![recipient_fact, recipient_signature, local_fact]))
}

pub fn create_key_frontier(
    ctx: &CommandContext<'_>,
    input: CreateKeyFrontier,
) -> Result<CommandOutput<CreateKeyFrontierReceipt>, String> {
    let endpoint = auth::endpoint::author::local_endpoint(ctx.store())?
        .ok_or_else(|| "local endpoint is not initialized".to_string())?;
    let membership = auth::workspace::queries::local_membership(ctx.store(), input.workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.endpoint_id != endpoint.endpoint {
        return Err("local endpoint membership does not match local endpoint".to_string());
    }
    let frontier_fact = auth::removal_frontier::author::authored_removal_frontier_fact(
        input.workspace_id,
        endpoint.endpoint,
        input.created_at_ms,
        endpoint.signing_secret,
    )?;
    let frontier_signature = auth::signature::author::sign_fact(
        input.workspace_id,
        &frontier_fact,
        &endpoint.signing_secret,
        input.created_at_ms,
    )?;
    let (_local_secret, local_secret_fact) = auth::local_key_secret::author::random_secret_fact(
        input.workspace_id,
        frontier_fact.id,
        endpoint.endpoint,
        input.created_at_ms,
    )?;
    let (_signer, signer_fact) = auth::local_signer_secret::author::signer_secret_fact(
        input.workspace_id,
        endpoint.endpoint,
        endpoint.signing_public_key,
        endpoint.signing_secret,
        input.created_at_ms,
    )?;
    Ok(CommandOutput::new(CreateKeyFrontierReceipt {
        workspace_id: input.workspace_id,
        removal_frontier_id: frontier_fact.id,
        local_key_secret_id: local_secret_fact.id,
        local_signer_secret_id: signer_fact.id,
    })
    .with_facts(vec![
        frontier_fact,
        frontier_signature,
        local_secret_fact,
        signer_fact,
    ]))
}

pub fn latest_local_recipient_key(
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
    let row = super::queries::decode_key_wrap_row(&key, &value)?;
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

pub fn local_key_secret_frontiers(runtime: &Runtime, workspace_id: FactId) -> Vec<FactId> {
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

pub fn workspace_key_wrap_count(runtime: &Runtime, workspace_id: FactId) -> Result<usize, String> {
    Ok(runtime
        .store()
        .table_rows(super::KEY_WRAP_ROWS)
        .map_err(|err| format!("load key wraps: {err}"))?
        .into_iter()
        .filter_map(|(key, value)| super::queries::decode_key_wrap_row(&key, &value).ok())
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

fn history_leaf_rows(
    store: &crate::core::store::Store,
    workspace_id: FactId,
) -> Result<Vec<HistoryLeafRow>, String> {
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

pub fn create_history_node(
    runtime: &Runtime,
    input: CreateHistoryNode,
) -> Result<CommandOutput<CreateHistoryNodeReceipt>, String> {
    if history_source_is_tombstoned(runtime, input.source_secret_id)? {
        return Err("history node source fact is missing".to_string());
    }
    let source = runtime
        .facts()
        .find(|fact| fact.id == input.source_secret_id)
        .ok_or_else(|| "history node source fact is missing".to_string())?;
    let (owner_endpoint_id, source_secret) =
        history_source_material(&source, input.workspace_id, input.removal_frontier_id)?;
    if input.tombstone_node_id != [0; 32] {
        let tombstone = runtime
            .facts()
            .find(|fact| fact.id == input.tombstone_node_id)
            .ok_or_else(|| "history node tombstone fact is missing".to_string())?;
        local_history_layout_decode::decode_local_history_node_secret(&tombstone.bytes)
            .map_err(|_| "history node tombstone fact is not a history node".to_string())?;
    }
    let mut info = Vec::with_capacity(32 + 32 + 8 + 8 + 32);
    info.extend_from_slice(&input.workspace_id);
    info.extend_from_slice(&input.removal_frontier_id);
    info.extend_from_slice(&input.range_start.to_be_bytes());
    info.extend_from_slice(&input.range_width.to_be_bytes());
    info.extend_from_slice(&input.tombstone_node_id);
    let node_secret =
        crate::core::crypto::blake3_keyed_hash(&source_secret, b"topo:key-node:v1", &info);
    let (_node, fact) = auth::local_history_node_secret::author::history_node_secret_fact(
        input.workspace_id,
        input.removal_frontier_id,
        owner_endpoint_id,
        input.source_secret_id,
        input.range_start,
        input.range_width,
        TIME_TREE_BIT_DEPTH,
        [0; 32],
        input.tombstone_node_id,
        node_secret,
        input.created_at_ms,
    )?;
    Ok(CommandOutput::new(CreateHistoryNodeReceipt {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        local_history_node_secret_id: fact.id,
        source_secret_id: input.source_secret_id,
        range_start: input.range_start,
        range_width: input.range_width,
        tombstone_node_id: input.tombstone_node_id,
    })
    .with_facts(vec![fact]))
}

pub fn chop_now(runtime: &mut Runtime, input: ChopNow) -> Result<ChopNowReceipt, String> {
    apply_retention_floor(runtime, input)?;

    let local_key_secret_ids = runtime
        .facts()
        .filter_map(|fact| {
            local_key_secret_layout_decode::decode_local_key_secret(fact.body())
                .ok()
                .filter(|secret| secret.workspace_id == input.workspace_id)
                .map(|_| fact.id)
        })
        .collect::<Vec<_>>();
    if !local_key_secret_ids.is_empty() {
        rotate_recipient_for_chop(runtime, input)?;
    }
    let retirement_facts = local_key_secret_ids
        .iter()
        .map(|fact_id| {
            auth::local_secret_retirement::author::chop_retirement_fact(
                input.workspace_id,
                *fact_id,
                input.floor_minute,
                input.created_at_ms,
            )
            .map(|(_retirement, fact)| fact)
        })
        .collect::<Result<Vec<_>, _>>()?;
    runtime.submit_facts(retirement_facts)?;
    runtime.process_all_work_until_idle(4, 512)?;
    Ok(ChopNowReceipt {
        workspace_id: input.workspace_id,
        floor_minute: input.floor_minute,
        subtree_tombstones_written: local_key_secret_ids.len(),
        boundary_descend_tombstones_written: 0,
        right_side_siblings_materialized: 0,
        purged_secret_bytes: 0,
        subsumed_message_tombstones_gcd: 0,
        subsumed_leaf_tombstones_gcd: 0,
    })
}

fn apply_retention_floor(runtime: &mut Runtime, input: ChopNow) -> Result<(), String> {
    let Some(active_policy) = content::retention_policy::queries::active_for_workspace(
        runtime.store(),
        input.workspace_id,
    )?
    else {
        return Ok(());
    };
    let output = content::retention_policy::commands::author_set_with_auto_floor(
        runtime.store(),
        content::retention_policy::commands::AuthorPolicy {
            workspace_id: input.workspace_id,
            now_ms: input.created_at_ms,
            ttl_minutes: active_policy.ttl_minutes,
            explicit_floor: Some(input.floor_minute),
        },
    )?;
    runtime.submit_command_output(output)?;
    runtime.process_all_work_until_idle(4, 512)?;
    Ok(())
}

fn rotate_recipient_for_chop(runtime: &mut Runtime, input: ChopNow) -> Result<(), String> {
    if let Some(previous) = latest_local_recipient_key(runtime, input.workspace_id)? {
        let clock = FixedClock(input.created_at_ms);
        let vault = KeyMaterialVault::new(runtime.store());
        let output = {
            let ctx = runtime.command_context(&clock, &vault);
            create_recipient_key(
                &ctx,
                CreateRecipientKey {
                    created_at_ms: input.created_at_ms,
                    workspace_id: input.workspace_id,
                    previous_recipient_key_id: previous,
                },
            )?
        };
        let _ = runtime.submit_command_output(output)?;
        runtime.process_all_work_until_idle(4, 512)?;
    }
    Ok(())
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

fn history_source_material(
    fact: &Fact,
    workspace_id: FactId,
    frontier_id: FactId,
) -> Result<(FactId, [u8; 32]), String> {
    if let Ok(root) = local_key_secret_layout_decode::decode_local_key_secret(fact.body()) {
        if root.workspace_id != workspace_id || root.frontier_id != frontier_id {
            return Err("history node source workspace or frontier mismatch".to_string());
        }
        return Ok((root.owner_endpoint_id, root.key_secret));
    }
    let node = local_history_layout_decode::decode_local_history_node_secret(fact.body())
        .map_err(|_| "history node source fact is missing".to_string())?;
    if node.workspace_id != workspace_id || node.frontier_id != frontier_id {
        return Err("history node source workspace or frontier mismatch".to_string());
    }
    Ok((node.owner_endpoint_id, node.node_secret))
}

fn history_source_is_tombstoned(
    runtime: &Runtime,
    source_secret_id: FactId,
) -> Result<bool, String> {
    for fact in runtime.facts() {
        let Ok(node) = local_history_layout_decode::decode_local_history_node_secret(fact.body())
        else {
            continue;
        };
        if node.tombstone_node_id == source_secret_id {
            return Ok(true);
        }
    }
    Ok(false)
}

struct FixedClock(u64);

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        self.0
    }
}

pub struct KeyMaterialVault<'a> {
    store: &'a Store,
}

impl<'a> KeyMaterialVault<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }
}

impl IdentityVault for KeyMaterialVault<'_> {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        let endpoint = auth::endpoint::author::local_endpoint(self.store)?
            .ok_or_else(|| "local endpoint is not initialized".to_string())?;
        let membership = auth::workspace::queries::local_membership(self.store, workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
        if membership.endpoint_id != endpoint.endpoint {
            return Err("local endpoint membership does not match local endpoint".to_string());
        }
        if membership.signing_public_key != endpoint.signing_public_key {
            return Err(
                "local endpoint signing key does not match workspace membership".to_string(),
            );
        }
        Ok(LocalSigningCapability {
            workspace_id,
            signer_id: endpoint.endpoint,
            public_key: endpoint.signing_public_key,
            private_key: endpoint.signing_secret,
        })
    }

    fn local_encryption_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        Err("local encryption capability is not configured for this command".to_string())
    }
}

//! User-facing encryption command constructors.

use crate::core::command_context::{
    CommandClock, CommandContext, CommandOutput, IdentityVault, LocalEncryptionCapability,
    LocalSigningCapability, WorkspaceId,
};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::event_modules::{
    identity_endpoint, identity_endpoint_shared, identity_workspace, local_history_node_secret,
    signed_fact,
};
use crate::protocol::runtime::ProtocolRuntime;

use super::fact::{
    LocalKeySecretFact, LocalRecipientKeyFact, RecipientKeyFact, RemovalFrontierFact,
};
use super::{layout, matchers};

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
    pub purged_event_bytes: usize,
    pub subsumed_message_tombstones_gcd: usize,
    pub subsumed_leaf_tombstones_gcd: usize,
}

pub fn create_recipient_key(
    ctx: &CommandContext<'_>,
    input: CreateRecipientKey,
) -> Result<CommandOutput<CreateRecipientKeyReceipt>, String> {
    let membership =
        identity_workspace::local_membership::local_membership(ctx.store(), input.workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.endpoint_role != identity_endpoint_shared::fact::EndpointRole::Device {
        return Err("local endpoint role cannot receive key wraps".to_string());
    }
    let recipient_secret = crypto::random_x25519_private_key();
    let recipient_key = crypto::x25519_public_key(&recipient_secret);
    let recipient = RecipientKeyFact {
        workspace_id: input.workspace_id,
        endpoint_id: membership.endpoint_id,
        recipient_key,
        previous_recipient_key_id: input.previous_recipient_key_id,
        created_at_ms: input.created_at_ms,
    };
    let recipient_fact = Fact::new(
        matchers::workspace_scope(input.workspace_id),
        input.created_at_ms,
        layout::encode_recipient_key(&recipient)?,
    );
    let local = LocalRecipientKeyFact {
        workspace_id: input.workspace_id,
        recipient_key_id: recipient_fact.id,
        recipient_key,
        recipient_secret,
    };
    let local_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        layout::encode_local_recipient_key(&local)?,
    );
    Ok(CommandOutput::new(CreateRecipientKeyReceipt {
        local_recipient_key_id: local_fact.id,
        recipient_key_id: recipient_fact.id,
        recipient_key,
    })
    .with_facts(vec![recipient_fact, local_fact]))
}

pub fn create_key_frontier(
    ctx: &CommandContext<'_>,
    input: CreateKeyFrontier,
) -> Result<CommandOutput<CreateKeyFrontierReceipt>, String> {
    let endpoint = identity_endpoint::local_endpoint::local_endpoint(ctx.store())?
        .ok_or_else(|| "local endpoint is not initialized".to_string())?;
    let membership =
        identity_workspace::local_membership::local_membership(ctx.store(), input.workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.endpoint_id != endpoint.endpoint {
        return Err("local endpoint membership does not match local endpoint".to_string());
    }
    let frontier = RemovalFrontierFact {
        workspace_id: input.workspace_id,
        owner_endpoint_id: endpoint.endpoint,
        created_at_ms: input.created_at_ms,
    };
    let frontier_fact = Fact::new(
        matchers::workspace_scope(input.workspace_id),
        input.created_at_ms,
        layout::encode_removal_frontier(&frontier)?,
    );
    let local_secret = LocalKeySecretFact {
        workspace_id: input.workspace_id,
        frontier_id: frontier_fact.id,
        owner_endpoint_id: endpoint.endpoint,
        created_at_ms: input.created_at_ms,
        key_secret: crypto::random_xchacha20poly1305_key(),
    };
    let local_secret_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        layout::encode_local_key_secret(&local_secret)?,
    );
    let signer = signed_fact::fact::LocalSignerSecretFact {
        workspace_id: input.workspace_id,
        signer_id: endpoint.endpoint,
        public_key: endpoint.signing_public_key,
        private_key: endpoint.signing_secret,
    };
    let signer_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        signed_fact::layout::encode_local_signer_secret(&signer)?,
    );
    Ok(CommandOutput::new(CreateKeyFrontierReceipt {
        workspace_id: input.workspace_id,
        removal_frontier_id: frontier_fact.id,
        local_key_secret_id: local_secret_fact.id,
        local_signer_secret_id: signer_fact.id,
    })
    .with_facts(vec![frontier_fact, local_secret_fact, signer_fact]))
}

pub fn latest_local_recipient_key(
    runtime: &ProtocolRuntime,
    workspace_id: FactId,
) -> Result<Option<FactId>, String> {
    let mut latest = None;
    for fact in runtime.facts() {
        let Ok(local) = layout::decode_local_recipient_key(&fact.bytes) else {
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
    runtime: &ProtocolRuntime,
    workspace_id: FactId,
) -> Result<Option<FactId>, String> {
    latest_local_recipient_key(runtime, workspace_id)
}

pub fn lookup_key_wrap(
    runtime: &ProtocolRuntime,
    query: KeyWrapQuery,
) -> Result<KeyWrapLookup, String> {
    if recipient_key_is_superseded(runtime, query.workspace_id, query.recipient_key_id)? {
        return Err("recipient key is missing or superseded".to_string());
    }
    let key = layout::frontier_root_key_wrap_coordinate_key(
        query.workspace_id,
        query.removal_frontier_id,
        query.recipient_key_id,
    );
    let value = runtime
        .store()
        .table_row(super::rows::KEY_WRAP_ROWS, &key)
        .map_err(|err| format!("load key wrap row: {err}"))?
        .ok_or_else(|| "key wrap is not available yet".to_string())?;
    let row = super::rows::decode_key_wrap_row(&key, &value)?;
    Ok(KeyWrapLookup {
        workspace_id: query.workspace_id,
        removal_frontier_id: query.removal_frontier_id,
        recipient_key_id: query.recipient_key_id,
        key_wrap_id: row.key_wrap_id,
    })
}

pub fn key_access(
    runtime: &ProtocolRuntime,
    query: KeyAccessQuery,
) -> Result<KeyAccessStatus, String> {
    let access = runtime.facts().any(|fact| {
        layout::decode_local_key_secret(&fact.bytes)
            .map(|secret| {
                secret.workspace_id == query.workspace_id
                    && secret.frontier_id == query.removal_frontier_id
            })
            .unwrap_or(false)
    });
    Ok(KeyAccessStatus {
        workspace_id: query.workspace_id,
        removal_frontier_id: query.removal_frontier_id,
        access,
    })
}

pub fn create_history_node(
    runtime: &ProtocolRuntime,
    input: CreateHistoryNode,
) -> Result<CommandOutput<CreateHistoryNodeReceipt>, String> {
    if history_source_is_tombstoned(runtime, input.source_secret_id)? {
        return Err("history node source event is missing".to_string());
    }
    let source = runtime
        .facts()
        .find(|fact| fact.id == input.source_secret_id)
        .ok_or_else(|| "history node source event is missing".to_string())?;
    let (owner_endpoint_id, source_secret) =
        history_source_material(source, input.workspace_id, input.removal_frontier_id)?;
    if input.tombstone_node_id != [0; 32] {
        let tombstone = runtime
            .facts()
            .find(|fact| fact.id == input.tombstone_node_id)
            .ok_or_else(|| "history node tombstone event is missing".to_string())?;
        layout::decode_local_history_node_secret(&tombstone.bytes)
            .map_err(|_| "history node tombstone event is not a history node".to_string())?;
    }
    let mut info = Vec::with_capacity(32 + 32 + 8 + 8 + 32);
    info.extend_from_slice(&input.workspace_id);
    info.extend_from_slice(&input.removal_frontier_id);
    info.extend_from_slice(&input.range_start.to_be_bytes());
    info.extend_from_slice(&input.range_width.to_be_bytes());
    info.extend_from_slice(&input.tombstone_node_id);
    let node_secret =
        crate::core::crypto::blake3_keyed_hash(&source_secret, b"topo:key-node:v1", &info);
    let node = super::fact::LocalHistoryNodeSecretFact {
        workspace_id: input.workspace_id,
        frontier_id: input.removal_frontier_id,
        owner_endpoint_id,
        source_secret_id: input.source_secret_id,
        range_start: input.range_start,
        range_width: input.range_width,
        bit_depth: local_history_node_secret::fact::TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        tombstone_node_id: input.tombstone_node_id,
        node_secret,
    };
    let fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        layout::encode_local_history_node_secret(&node)?,
    );
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

pub fn chop_now(runtime: &mut ProtocolRuntime, input: ChopNow) -> Result<ChopNowReceipt, String> {
    let old_recipient = latest_local_recipient_key(runtime, input.workspace_id)?;
    if let Some(previous) = old_recipient {
        let clock = FixedClock(input.created_at_ms);
        let vault = EmptyVault;
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
        drain_runtime(runtime)?;
    }
    let local_key_secret_ids = runtime
        .facts()
        .filter_map(|fact| {
            layout::decode_local_key_secret(&fact.bytes)
                .ok()
                .filter(|secret| secret.workspace_id == input.workspace_id)
                .map(|_| fact.id)
        })
        .collect::<Vec<_>>();
    for fact_id in &local_key_secret_ids {
        runtime.purge_fact(*fact_id);
    }
    drain_runtime(runtime)?;
    Ok(ChopNowReceipt {
        workspace_id: input.workspace_id,
        floor_minute: input.floor_minute,
        subtree_tombstones_written: local_key_secret_ids.len(),
        boundary_descend_tombstones_written: 0,
        right_side_siblings_materialized: 0,
        purged_event_bytes: 0,
        subsumed_message_tombstones_gcd: 0,
        subsumed_leaf_tombstones_gcd: 0,
    })
}

fn recipient_key_is_superseded(
    runtime: &ProtocolRuntime,
    workspace_id: FactId,
    recipient_key_id: FactId,
) -> Result<bool, String> {
    let mut target_endpoint = None;
    for fact in runtime.facts() {
        if fact.id != recipient_key_id {
            continue;
        }
        let recipient = layout::decode_recipient_key(&fact.bytes)?;
        if recipient.workspace_id == workspace_id {
            target_endpoint = Some(recipient.endpoint_id);
        }
    }
    let Some(endpoint_id) = target_endpoint else {
        return Ok(false);
    };
    for fact in runtime.facts() {
        let Ok(recipient) = layout::decode_recipient_key(&fact.bytes) else {
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
    if let Ok(root) = layout::decode_local_key_secret(&fact.bytes) {
        if root.workspace_id != workspace_id || root.frontier_id != frontier_id {
            return Err("history node source workspace or frontier mismatch".to_string());
        }
        return Ok((root.owner_endpoint_id, root.key_secret));
    }
    let node = layout::decode_local_history_node_secret(&fact.bytes)
        .map_err(|_| "history node source event is missing".to_string())?;
    if node.workspace_id != workspace_id || node.frontier_id != frontier_id {
        return Err("history node source workspace or frontier mismatch".to_string());
    }
    Ok((node.owner_endpoint_id, node.node_secret))
}

fn history_source_is_tombstoned(
    runtime: &ProtocolRuntime,
    source_secret_id: FactId,
) -> Result<bool, String> {
    for fact in runtime.facts() {
        let Ok(node) = layout::decode_local_history_node_secret(&fact.bytes) else {
            continue;
        };
        if node.tombstone_node_id == source_secret_id {
            return Ok(true);
        }
    }
    Ok(false)
}

fn drain_runtime(runtime: &mut ProtocolRuntime) -> Result<(), String> {
    for _ in 0..4 {
        runtime.drain_projection_until_idle(8, 512)?;
        let dispatched = runtime.dispatch_intents(512)?;
        if dispatched.handled == 0 && dispatched.facts == 0 && dispatched.intents == 0 {
            runtime.drain_projection_until_idle(8, 512)?;
            return Ok(());
        }
    }
    Ok(())
}

struct FixedClock(u64);

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        self.0
    }
}

struct EmptyVault;

impl IdentityVault for EmptyVault {
    fn local_signing_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        Err("local signing capability is not configured for this command".to_string())
    }

    fn local_encryption_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        Err("local encryption capability is not configured for this command".to_string())
    }
}

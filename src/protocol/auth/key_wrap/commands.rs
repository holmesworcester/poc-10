//! User-facing auth key-material command authors.
//!
//! These commands are the local entry points for creating recipient keys,
//! removal frontiers, history nodes, and key wraps. They read projected auth
//! state, construct facts, and return receipts suitable for CLI output.

use crate::core::command::CommandOutput;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::core::runtime::Runtime;
use crate::core::store::Store;
use crate::protocol::auth;
use crate::protocol::auth::local_history_node_secret::fact::TIME_TREE_BIT_DEPTH;

use crate::protocol::auth::local_history_node_secret::project::decode as local_history_layout_decode;
use crate::protocol::auth::local_key_secret::project::decode as local_key_secret_layout_decode;

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

pub fn create_recipient_key(
    store: &Store,
    input: CreateRecipientKey,
) -> Result<CommandOutput<CreateRecipientKeyReceipt>, String> {
    let membership = auth::workspace::queries::local_membership(store, input.workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.endpoint_role != auth::endpoint_shared::fact::EndpointRole::Device {
        return Err("local endpoint role cannot receive key wraps".to_string());
    }
    let signing = auth::endpoint::commands::local_signing_capability(store, input.workspace_id)?;
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
    store: &Store,
    input: CreateKeyFrontier,
) -> Result<CommandOutput<CreateKeyFrontierReceipt>, String> {
    let endpoint = auth::endpoint::author::local_endpoint(store)?
        .ok_or_else(|| "local endpoint is not initialized".to_string())?;
    let membership = auth::workspace::queries::local_membership(store, input.workspace_id)?
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

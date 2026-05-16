use crate::core::facts::Fact;
use crate::event_modules::encryption;
use crate::event_modules::removal_frontier;

use super::super::fact::{
    mask_prefix_to_depth, LocalHistoryNodeSecretFact, TIME_TREE_BIT_DEPTH, TRIE_LEAF_BIT_DEPTH,
};
use super::super::layout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SourceKind {
    Root,
    HistoryNode(HistoryNodeAddress),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HistoryNodeAddress {
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: [u8; 32],
}

pub(super) fn validate_frontier(
    frontier_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if frontier_fact.id != node.removal_frontier_id {
        return Err("local history node frontier context payload id mismatch".to_string());
    }
    let frontier = removal_frontier::layout::decode_fact(&frontier_fact.bytes).map_err(|_| {
        "local history node frontier context must be a removal frontier".to_string()
    })?;
    if frontier.workspace_id != node.workspace_id {
        return Err("local history node frontier workspace mismatch".to_string());
    }
    Ok(())
}

pub(super) fn validate_source(
    source_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<SourceKind, String> {
    if source_fact.id != node.source_secret_id {
        return Err("local history node source context payload id mismatch".to_string());
    }
    if let Ok(source) = layout::decode_fact(&source_fact.bytes) {
        if source.workspace_id != node.workspace_id
            || source.removal_frontier_id != node.removal_frontier_id
        {
            return Err("local history node source workspace or frontier mismatch".to_string());
        }
        return Ok(SourceKind::HistoryNode(HistoryNodeAddress {
            workspace_id: source.workspace_id,
            frontier_id: source.removal_frontier_id,
            range_start: source.range_start,
            range_width: source.range_width,
            bit_depth: source.bit_depth,
            event_id_prefix: source.event_id_prefix,
        }));
    }
    if let Ok(source) = encryption::layout::decode_local_key_secret(&source_fact.bytes) {
        if source.workspace_id != node.workspace_id
            || source.frontier_id != node.removal_frontier_id
        {
            return Err("local history node source workspace or frontier mismatch".to_string());
        }
        return Ok(SourceKind::Root);
    }
    if let Ok(source) = encryption::layout::decode_local_history_node_secret(&source_fact.bytes) {
        if source.workspace_id != node.workspace_id
            || source.frontier_id != node.removal_frontier_id
        {
            return Err("local history node source workspace or frontier mismatch".to_string());
        }
        return Ok(SourceKind::HistoryNode(HistoryNodeAddress {
            workspace_id: source.workspace_id,
            frontier_id: source.frontier_id,
            range_start: source.range_start,
            range_width: source.range_width,
            bit_depth: source.bit_depth,
            event_id_prefix: source.event_id_prefix,
        }));
    }
    Err("local history node source context is not key material".to_string())
}

pub(super) fn validate_tombstone(
    tombstone_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if tombstone_fact.id != node.tombstone_node_id {
        return Err("local history node tombstone context payload id mismatch".to_string());
    }
    let tombstone = if let Ok(tombstone) = layout::decode_fact(&tombstone_fact.bytes) {
        HistoryNodeAddress {
            workspace_id: tombstone.workspace_id,
            frontier_id: tombstone.removal_frontier_id,
            range_start: tombstone.range_start,
            range_width: tombstone.range_width,
            bit_depth: tombstone.bit_depth,
            event_id_prefix: tombstone.event_id_prefix,
        }
    } else if let Ok(tombstone) =
        encryption::layout::decode_local_history_node_secret(&tombstone_fact.bytes)
    {
        HistoryNodeAddress {
            workspace_id: tombstone.workspace_id,
            frontier_id: tombstone.frontier_id,
            range_start: tombstone.range_start,
            range_width: tombstone.range_width,
            bit_depth: tombstone.bit_depth,
            event_id_prefix: tombstone.event_id_prefix,
        }
    } else {
        return Err("local history node tombstone context is not a history node".to_string());
    };
    if tombstone.workspace_id != node.workspace_id
        || tombstone.frontier_id != node.removal_frontier_id
    {
        return Err("local history node tombstone workspace or frontier mismatch".to_string());
    }
    if tombstone.range_start == node.range_start
        && tombstone.range_width == node.range_width
        && tombstone.bit_depth == node.bit_depth
        && tombstone.event_id_prefix == node.event_id_prefix
    {
        return Err("local history node cannot tombstone its own coordinate".to_string());
    }
    Ok(())
}

pub(super) fn validate_child_addressing(
    source: &HistoryNodeAddress,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if node.tombstone_node_id != [0; 32] {
        return Ok(());
    }
    if node.bit_depth > TIME_TREE_BIT_DEPTH {
        if source.range_start != node.range_start {
            return Err(
                "local history node trie child must share its parent's range_start".to_string(),
            );
        }
        if node.bit_depth <= source.bit_depth {
            return Err(
                "local history node trie child bit_depth must exceed its parent's".to_string(),
            );
        }
        if source.bit_depth >= TRIE_LEAF_BIT_DEPTH {
            return Err("local history node leaf cannot have children".to_string());
        }
        if mask_prefix_to_depth(node.event_id_prefix, source.bit_depth) != source.event_id_prefix {
            return Err(
                "local history node trie child prefix must extend its parent's prefix".to_string(),
            );
        }
        return Ok(());
    }
    if source.bit_depth != TIME_TREE_BIT_DEPTH {
        return Err(
            "local history node time-tree child cannot descend from a trie node".to_string(),
        );
    }
    if source.range_width <= node.range_width {
        return Err(
            "local history node time-tree child must have a strictly smaller range_width"
                .to_string(),
        );
    }
    let parent_end = source
        .range_start
        .checked_add(source.range_width)
        .ok_or_else(|| "local history node parent range overflow".to_string())?;
    let child_end = node
        .range_start
        .checked_add(node.range_width)
        .ok_or_else(|| "local history node child range overflow".to_string())?;
    if node.range_start < source.range_start || child_end > parent_end {
        return Err(
            "local history node time-tree child range is outside its parent's range".to_string(),
        );
    }
    Ok(())
}

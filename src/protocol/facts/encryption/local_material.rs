use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::protocol::facts::encryption::fact::{LocalHistoryNodeSecretFact, LocalKeySecretFact};
use crate::protocol::facts::encryption::layout;
use crate::protocol::facts::encryption::local_history_node_secret::fact::{
    mask_prefix_to_depth, TIME_TREE_BIT_DEPTH, TRIE_LEAF_BIT_DEPTH,
};
use crate::protocol::matchers;
use crate::protocol::matchers as history_matchers;

use super::validation::{matched_payload_fact, require_local_scope};

pub(super) fn project_local_key_secret(
    fact: &Fact,
    projection_context: &ProjectionContext,
    secret: LocalKeySecretFact,
) -> Result<ProjectionOutput, String> {
    let scope = crate::protocol::matchers::workspace_scope(secret.workspace_id);
    require_local_scope(fact)?;
    let frontier_need = matchers::frontier_need(fact.id, scope.clone(), secret.frontier_id);
    let Some(frontier_fact) = matched_payload_fact(projection_context, &frontier_need) else {
        return Ok(ProjectionOutput::new().need(frontier_need));
    };
    validate_local_key_frontier(frontier_fact, &secret)?;

    Ok(ProjectionOutput::new()
        .need(frontier_need)
        .offer(matchers::frontier_root_wrap_source_offer(
            fact.id,
            scope.clone(),
            secret.workspace_id,
            secret.frontier_id,
            secret.owner_endpoint_id,
            secret.created_at_ms,
        ))
        .offer(history_matchers::source_secret_offer(fact.id, fact.id))
        .offer(crate::protocol::matchers::secret_offer(
            fact.id,
            scope,
            secret.workspace_id,
            secret.frontier_id,
            0,
            u64::MAX,
            0,
            [0; 32],
        )))
}

pub(super) fn project_local_history_node_secret(
    fact: &Fact,
    projection_context: &ProjectionContext,
    node: LocalHistoryNodeSecretFact,
) -> Result<ProjectionOutput, String> {
    let scope = crate::protocol::matchers::workspace_scope(node.workspace_id);
    require_local_scope(fact)?;
    let frontier_need = matchers::frontier_need(fact.id, scope.clone(), node.frontier_id);
    let source_need = history_matchers::source_secret_need(fact.id, node.source_secret_id);
    let tombstone_need = if node.tombstone_node_id == [0; 32] {
        None
    } else {
        Some(history_matchers::source_secret_need(
            fact.id,
            node.tombstone_node_id,
        ))
    };
    let mut waiting = ProjectionOutput::new()
        .need(frontier_need.clone())
        .need(source_need.clone());
    if let Some(need) = &tombstone_need {
        waiting = waiting.need(need.clone());
    }

    let Some(frontier_fact) = matched_payload_fact(projection_context, &frontier_need) else {
        return Ok(waiting);
    };
    let Some(source_fact) = matched_payload_fact(projection_context, &source_need) else {
        return Ok(waiting);
    };
    let tombstone_fact = if let Some(need) = &tombstone_need {
        let Some(payload) = matched_payload_fact(projection_context, need) else {
            return Ok(waiting);
        };
        Some(payload)
    } else {
        None
    };

    validate_history_frontier(frontier_fact, &node)?;
    let source = validate_history_source(source_fact, &node)?;
    match source {
        HistorySourceKind::Root => {
            if node.tombstone_node_id != [0; 32] {
                return Err(
                    "local history node cannot tombstone without a history source".to_string(),
                );
            }
        }
        HistorySourceKind::HistoryNode(source_node) => {
            validate_history_child_addressing(&source_node, &node)?;
            if node.tombstone_node_id != [0; 32] && node.tombstone_node_id != node.source_secret_id
            {
                return Err(
                    "local history node tombstone must retire its source path node".to_string(),
                );
            }
        }
    }
    if let Some(tombstone) = tombstone_fact {
        validate_history_tombstone(tombstone, &node)?;
    }

    let end_minute = node
        .range_start
        .checked_add(node.range_width - 1)
        .ok_or_else(|| "history node range end overflow".to_string())?;
    if node.bit_depth % 8 != 0 {
        return Err(
            "content-message history coverage only accepts byte-aligned prefixes".to_string(),
        );
    }
    let prefix_bytes = (node.bit_depth / 8)
        .try_into()
        .map_err(|_| "history node prefix byte width overflow".to_string())?;
    Ok(waiting
        .offer(matchers::history_node_wrap_source_offer(
            fact.id,
            scope.clone(),
            node.workspace_id,
            node.frontier_id,
            node.owner_endpoint_id,
            node.range_start,
            node.range_width,
            node.bit_depth,
            node.fact_id_prefix,
        ))
        .offer(history_matchers::source_secret_offer(fact.id, fact.id))
        .offer(crate::protocol::matchers::secret_offer(
            fact.id,
            scope,
            node.workspace_id,
            node.frontier_id,
            node.range_start,
            end_minute,
            prefix_bytes,
            node.fact_id_prefix,
        )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HistorySourceKind {
    Root,
    HistoryNode(HistoryNodeAddress),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryNodeAddress {
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    owner_endpoint_id: [u8; 32],
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: [u8; 32],
}

fn validate_local_key_frontier(
    frontier_fact: &Fact,
    secret: &LocalKeySecretFact,
) -> Result<(), String> {
    if frontier_fact.id != secret.frontier_id {
        return Err("local key secret frontier context payload id mismatch".to_string());
    }
    let frontier = layout::decode_removal_frontier(&frontier_fact.bytes)
        .map_err(|_| "local key secret frontier context must be a removal frontier".to_string())?;
    if frontier.workspace_id != secret.workspace_id {
        return Err("local key secret frontier workspace mismatch".to_string());
    }
    if frontier.owner_endpoint_id != secret.owner_endpoint_id {
        return Err("local key secret frontier owner mismatch".to_string());
    }
    Ok(())
}

fn validate_history_frontier(
    frontier_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if frontier_fact.id != node.frontier_id {
        return Err("local history node frontier context payload id mismatch".to_string());
    }
    let frontier = layout::decode_removal_frontier(&frontier_fact.bytes).map_err(|_| {
        "local history node frontier context must be a removal frontier".to_string()
    })?;
    if frontier.workspace_id != node.workspace_id {
        return Err("local history node frontier workspace mismatch".to_string());
    }
    if frontier.owner_endpoint_id != node.owner_endpoint_id {
        return Err("local history node frontier owner mismatch".to_string());
    }
    Ok(())
}

fn validate_history_source(
    source_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<HistorySourceKind, String> {
    if source_fact.id != node.source_secret_id {
        return Err("local history node source context payload id mismatch".to_string());
    }
    if let Ok(source) = layout::decode_local_key_secret(&source_fact.bytes) {
        if source.workspace_id != node.workspace_id
            || source.frontier_id != node.frontier_id
            || source.owner_endpoint_id != node.owner_endpoint_id
        {
            return Err(
                "local history node source workspace, frontier, or owner mismatch".to_string(),
            );
        }
        return Ok(HistorySourceKind::Root);
    }
    if let Ok(source) = layout::decode_local_history_node_secret(&source_fact.bytes) {
        if source.workspace_id != node.workspace_id
            || source.frontier_id != node.frontier_id
            || source.owner_endpoint_id != node.owner_endpoint_id
        {
            return Err(
                "local history node source workspace, frontier, or owner mismatch".to_string(),
            );
        }
        return Ok(HistorySourceKind::HistoryNode(HistoryNodeAddress {
            workspace_id: source.workspace_id,
            frontier_id: source.frontier_id,
            owner_endpoint_id: source.owner_endpoint_id,
            range_start: source.range_start,
            range_width: source.range_width,
            bit_depth: source.bit_depth,
            fact_id_prefix: source.fact_id_prefix,
        }));
    }
    Err("local history node source context is not key material".to_string())
}

fn validate_history_tombstone(
    tombstone_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if tombstone_fact.id != node.tombstone_node_id {
        return Err("local history node tombstone context payload id mismatch".to_string());
    }
    let tombstone = layout::decode_local_history_node_secret(&tombstone_fact.bytes)
        .map_err(|_| "local history node tombstone context is not a history node".to_string())?;
    if tombstone.workspace_id != node.workspace_id
        || tombstone.frontier_id != node.frontier_id
        || tombstone.owner_endpoint_id != node.owner_endpoint_id
    {
        return Err(
            "local history node tombstone workspace, frontier, or owner mismatch".to_string(),
        );
    }
    if tombstone.range_start == node.range_start
        && tombstone.range_width == node.range_width
        && tombstone.bit_depth == node.bit_depth
        && tombstone.fact_id_prefix == node.fact_id_prefix
    {
        return Err("local history node cannot tombstone its own coordinate".to_string());
    }
    Ok(())
}

fn validate_history_child_addressing(
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
        if mask_prefix_to_depth(node.fact_id_prefix, source.bit_depth) != source.fact_id_prefix {
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

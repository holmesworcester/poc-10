//! Projection for local frontier-root and history-node secret facts.

use super::layout;
use crate::core::facts::Fact;
use crate::core::projection::ProjectionOutput;
use crate::event_modules::encryption::project::require_local_scope;
use crate::event_modules::encryption::wrap_source::context as wrap_source_context;
use crate::event_modules::sealed_message;

pub fn project_local_key_secret(fact: &Fact) -> Result<ProjectionOutput, String> {
    let secret = layout::decode_local_key_secret(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(secret.workspace_id);
    require_local_scope(fact)?;
    Ok(ProjectionOutput::new()
        .offer(wrap_source_context::frontier_root_wrap_source_offer(
            fact.id,
            scope.clone(),
            secret.workspace_id,
            secret.frontier_id,
            secret.owner_endpoint_id,
            secret.created_at_ms,
        ))
        .offer(sealed_message::context::secret_offer(
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

pub fn project_local_history_node_secret(fact: &Fact) -> Result<ProjectionOutput, String> {
    let node = layout::decode_local_history_node_secret(&fact.bytes)?;
    let scope = sealed_message::context::workspace_scope(node.workspace_id);
    require_local_scope(fact)?;
    let end_minute = node
        .range_start
        .checked_add(node.range_width - 1)
        .ok_or_else(|| "history node range end overflow".to_string())?;
    if node.bit_depth % 8 != 0 {
        return Err("sealed-message bridge only accepts byte-aligned history prefixes".to_string());
    }
    let prefix_bytes = (node.bit_depth / 8)
        .try_into()
        .map_err(|_| "history node prefix byte width overflow".to_string())?;
    Ok(ProjectionOutput::new()
        .offer(wrap_source_context::history_node_wrap_source_offer(
            fact.id,
            scope.clone(),
            node.workspace_id,
            node.frontier_id,
            node.owner_endpoint_id,
            node.range_start,
            node.range_width,
            node.bit_depth,
            node.event_id_prefix,
        ))
        .offer(sealed_message::context::secret_offer(
            fact.id,
            scope,
            node.workspace_id,
            node.frontier_id,
            node.range_start,
            end_minute,
            prefix_bytes,
            node.event_id_prefix,
        )))
}

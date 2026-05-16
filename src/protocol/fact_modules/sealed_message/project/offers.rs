use crate::core::facts::Fact;
use crate::core::projection::ProjectionOutput;

use super::super::layout;
use super::validation::require_fact_scope;
use crate::protocol::matchers;

pub(super) fn project_signer_pubkey(fact: &Fact) -> Result<ProjectionOutput, String> {
    let signer = layout::decode_signer_pubkey(&fact.bytes)?;
    Ok(ProjectionOutput::new().offer(matchers::signer_offer(
        fact.id,
        fact.scope.clone(),
        signer.signer_id,
    )))
}

pub(super) fn project_secret_node(fact: &Fact) -> Result<ProjectionOutput, String> {
    let node = layout::decode_secret_node(&fact.bytes)?;
    let scope = matchers::workspace_scope(node.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(matchers::secret_offer(
        fact.id,
        scope,
        node.workspace_id,
        node.frontier_id,
        node.start_minute,
        node.end_minute,
        node.prefix_bytes,
        node.leaf_prefix,
    )))
}

pub(super) fn project_message_deletion(fact: &Fact) -> Result<ProjectionOutput, String> {
    let deletion = layout::decode_message_deletion(&fact.bytes)?;
    let scope = matchers::workspace_scope(deletion.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(matchers::deletion_offer(
        fact.id,
        scope,
        deletion.target_id,
        deletion.author_user_id,
    )))
}

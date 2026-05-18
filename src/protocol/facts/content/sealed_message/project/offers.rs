use crate::core::facts::Fact;
use crate::core::projection::ProjectionOutput;

use super::super::fact::{MessageDeletionFact, SecretNodeFact, SignerPubkeyFact};
use super::validation::require_fact_scope;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

pub(super) fn project_signer_pubkey(
    fact: &Fact,
    signer: SignerPubkeyFact,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new().offer(matchers::signer_offer(
        fact.id,
        fact.scope.clone(),
        signer.signer_id,
    )))
}

pub(super) fn project_secret_node(
    fact: &Fact,
    node: SecretNodeFact,
) -> Result<ProjectionOutput, String> {
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

pub(super) fn project_message_deletion(
    fact: &Fact,
    deletion: MessageDeletionFact,
) -> Result<ProjectionOutput, String> {
    let scope = matchers::workspace_scope(deletion.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new()
        .offer(matchers::deletion_offer(
            fact.id,
            scope,
            deletion.target_id,
            deletion.author_user_id,
        ))
        .intent(share_fact_with_workspace_intent_for_fact(
            deletion.workspace_id,
            fact,
        )))
}

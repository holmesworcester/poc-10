//! Poc-10 sealed-message projector.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::context;
use super::intent::{self, OpenMessageIntent, PurgeEventIntent};
use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SealedMessageProjector;

impl SealedMessageProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SealedMessageProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(layout::TYPE_SEALED_MESSAGE) => project_message(fact, context),
            Some(layout::TYPE_SIGNER_PUBKEY) => project_signer_pubkey(fact),
            Some(layout::TYPE_SECRET_NODE) => project_secret_node(fact),
            Some(layout::TYPE_MESSAGE_DELETION) => project_message_deletion(fact),
            _ => Err("unknown sealed-message fact type".to_string()),
        }
    }
}

fn project_message(fact: &Fact, context: &ProjectionContext) -> Result<ProjectionOutput, String> {
    let message = layout::decode_sealed_message(&fact.bytes)?;
    let scope = context::workspace_scope(message.workspace_id);
    let signer_need = context::signer_need(fact.id, scope.clone(), message.signer_id);
    let deletion_need = context::deletion_need(fact.id, scope.clone(), fact.id);
    let secret_need = context::secret_need(
        fact.id,
        scope,
        message.workspace_id,
        message.frontier_id,
        message.minute,
        message.leaf_id,
    );
    let has_signer = context
        .offers()
        .iter()
        .any(|offer| offer.role == signer_need.role && offer.selector == signer_need.selector);
    let has_secret = context
        .offers()
        .iter()
        .any(|offer| offer.role == secret_need.role);
    let has_deletion = context
        .offers()
        .iter()
        .any(|offer| offer.role == deletion_need.role && offer.selector == deletion_need.selector);

    if has_deletion {
        return Ok(
            ProjectionOutput::new().intent(intent::purge_event_intent(PurgeEventIntent {
                workspace_id: message.workspace_id,
                message_id: fact.id,
            })),
        );
    }

    if has_signer && has_secret {
        return Ok(ProjectionOutput::new().need(deletion_need).intent(
            intent::open_message_intent(OpenMessageIntent {
                workspace_id: message.workspace_id,
                message_id: fact.id,
                minute: message.minute,
                leaf_id: message.leaf_id,
            }),
        ));
    }

    Ok(ProjectionOutput::new()
        .need(signer_need)
        .need(secret_need)
        .need(deletion_need))
}

fn project_signer_pubkey(fact: &Fact) -> Result<ProjectionOutput, String> {
    let signer = layout::decode_signer_pubkey(&fact.bytes)?;
    Ok(ProjectionOutput::new().offer(context::signer_offer(
        fact.id,
        fact.scope.clone(),
        signer.signer_id,
    )))
}

fn project_secret_node(fact: &Fact) -> Result<ProjectionOutput, String> {
    let node = layout::decode_secret_node(&fact.bytes)?;
    Ok(ProjectionOutput::new().offer(context::secret_offer(
        fact.id,
        fact.scope.clone(),
        node.workspace_id,
        node.frontier_id,
        node.start_minute,
        node.end_minute,
        node.prefix_bytes,
        node.leaf_prefix,
    )))
}

fn project_message_deletion(fact: &Fact) -> Result<ProjectionOutput, String> {
    let deletion = layout::decode_message_deletion(&fact.bytes)?;
    Ok(ProjectionOutput::new().offer(context::deletion_offer(
        fact.id,
        fact.scope.clone(),
        deletion.target_id,
    )))
}

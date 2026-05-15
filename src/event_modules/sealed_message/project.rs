//! Poc-10 sealed-message projector.

use crate::core::facts::Fact;
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::context;
use super::intent::{self, PurgeEventIntent, PURGE_REASON_AUTHOR_DELETION, PURGE_TARGET_MESSAGE};
use super::layout;
use super::rows::{
    message_key, message_tombstone_row, sealed_message_row, SealedMessageRow, MESSAGE_ROWS,
    SEALED_MESSAGE_ROWS,
};

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
    require_fact_scope(fact, &scope)?;
    let signer_need = context::signer_need(fact.id, scope.clone(), message.signer_id);
    let deletion_need =
        context::deletion_need(fact.id, scope.clone(), fact.id, message.author_user_id);
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
        .any(|offer| context::secret_offer_matches_need(&secret_need, offer));
    if let Some(reason_fact_id) = deletion_reason_fact_id(context, &deletion_need) {
        let row_key = message_key(message.workspace_id, fact.id);
        return Ok(ProjectionOutput::new()
            .intent(
                AtomicIntent::PutRow(message_tombstone_row(
                    message.workspace_id,
                    fact.id,
                    message.author_user_id,
                    message.created_at_ms,
                ))
                .into_intent(),
            )
            .intent(
                AtomicIntent::DeleteRow(TableDelete {
                    table: MESSAGE_ROWS,
                    key: row_key.clone(),
                })
                .into_intent(),
            )
            .intent(
                AtomicIntent::DeleteRow(TableDelete {
                    table: SEALED_MESSAGE_ROWS,
                    key: row_key,
                })
                .into_intent(),
            )
            .intent(intent::purge_event_intent(PurgeEventIntent {
                workspace_id: message.workspace_id,
                target_kind: PURGE_TARGET_MESSAGE,
                target_id: fact.id,
                reason_kind: PURGE_REASON_AUTHOR_DELETION,
                reason_fact_id,
            })));
    }

    if !has_signer {
        return Ok(ProjectionOutput::new()
            .need(signer_need)
            .need(secret_need)
            .need(deletion_need));
    }

    let sealed_row = AtomicIntent::PutRow(sealed_message_row(SealedMessageRow {
        workspace_id: message.workspace_id,
        message_id: fact.id,
        created_at_ms: message.created_at_ms,
        author_user_id: message.author_user_id,
        signer_id: message.signer_id,
        frontier_id: message.frontier_id,
        local_history_node_secret_id: message.local_history_node_secret_id,
        expires_at_minute: message.expires_at_minute,
        disappearing_setting_id: message.disappearing_setting_id,
        minute: message.minute,
        leaf_id: message.leaf_id,
        nonce: message.nonce,
        ciphertext: message.ciphertext.clone(),
    })?)
    .into_intent();

    if has_signer && has_secret {
        return Ok(ProjectionOutput::new()
            .need(deletion_need)
            .intent(sealed_row));
    }

    Ok(ProjectionOutput::new()
        .need(secret_need)
        .need(deletion_need)
        .intent(sealed_row))
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
    let scope = context::workspace_scope(node.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(context::secret_offer(
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

fn project_message_deletion(fact: &Fact) -> Result<ProjectionOutput, String> {
    let deletion = layout::decode_message_deletion(&fact.bytes)?;
    let scope = context::workspace_scope(deletion.workspace_id);
    require_fact_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(context::deletion_offer(
        fact.id,
        scope,
        deletion.target_id,
        deletion.author_user_id,
    )))
}

fn deletion_reason_fact_id(
    context: &ProjectionContext,
    need: &crate::core::context::ContextNeed,
) -> Option<crate::core::facts::FactId> {
    context
        .matched_context()
        .iter()
        .find(|matched| matched.need == *need)
        .map(|matched| matched.payload.id)
        .or_else(|| {
            context
                .offers()
                .iter()
                .find(|offer| offer.role == need.role && offer.selector == need.selector)
                .map(|offer| offer.payload_ref)
        })
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sealed-message fact scope does not match body workspace".to_string())
    }
}

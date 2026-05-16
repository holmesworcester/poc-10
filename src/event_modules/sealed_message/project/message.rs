use crate::core::facts::{Fact, FactId};
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::event_modules::signed_fact;

use super::super::fact::SealedMessageFact;
use super::super::intent::{
    self, PurgeEventIntent, PURGE_REASON_AUTHOR_DELETION, PURGE_TARGET_MESSAGE,
};
use super::super::layout;
use super::super::matchers;
use super::super::rows::{
    message_key, message_tombstone_row, sealed_message_row, SealedMessageRow, MESSAGE_ROWS,
    SEALED_MESSAGE_ROWS,
};
use super::validation::{
    has_matched_secret, require_fact_scope, validate_deletion_context, validate_signer_context,
};

pub(super) fn project_message(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let message = layout::decode_sealed_message(&fact.bytes)?;
    project_decoded_message(fact, context, message, None)
}

pub(super) fn project_signed_message(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
    if envelope.inner_type != layout::TYPE_SEALED_MESSAGE {
        return Err("signed fact does not contain a sealed message".to_string());
    }
    let message = layout::decode_sealed_message(&envelope.payload)?;
    if envelope.signer_id != message.signer_id {
        return Err("sealed message signer does not match signed envelope signer".to_string());
    }
    project_decoded_message(fact, context, message, Some(envelope.signer_public_key))
}

fn project_decoded_message(
    fact: &Fact,
    context: &ProjectionContext,
    message: SealedMessageFact,
    signed_public_key: Option<[u8; 32]>,
) -> Result<ProjectionOutput, String> {
    let scope = matchers::workspace_scope(message.workspace_id);
    require_fact_scope(fact, &scope)?;
    let signer_need = matchers::signer_need(fact.id, scope.clone(), message.signer_id);
    let deletion_need =
        matchers::deletion_need(fact.id, scope.clone(), fact.id, message.author_user_id);
    let secret_need = matchers::secret_need(
        fact.id,
        scope,
        message.workspace_id,
        message.frontier_id,
        message.minute,
        message.leaf_id,
    );
    if let Some(reason_fact_id) = deletion_reason_fact_id(context, &deletion_need, &message)? {
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

    let Some(signer_payload) = context.payload_for(&signer_need) else {
        return Ok(ProjectionOutput::new()
            .need(signer_need)
            .need(secret_need)
            .need(deletion_need));
    };
    validate_signer_context(
        signer_payload,
        &signer_need,
        message.signer_id,
        signed_public_key,
    )?;
    let has_secret = has_matched_secret(context, &secret_need)?;

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

    if has_secret {
        return Ok(ProjectionOutput::new()
            .need(deletion_need)
            .intent(sealed_row));
    }

    Ok(ProjectionOutput::new()
        .need(secret_need)
        .need(deletion_need)
        .intent(sealed_row))
}

fn deletion_reason_fact_id(
    context: &ProjectionContext,
    need: &crate::core::context::ContextNeed,
    message: &SealedMessageFact,
) -> Result<Option<FactId>, String> {
    let Some(payload) = context.payload_for(need) else {
        return Ok(None);
    };
    validate_deletion_context(payload, need, message)?;
    Ok(Some(payload.id))
}

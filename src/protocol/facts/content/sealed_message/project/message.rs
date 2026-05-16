use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput};
use crate::protocol::facts::encryption;
use crate::protocol::facts::identity::signed_fact;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::super::fact::SealedMessageFact;
use super::super::intent::{
    self, PurgeDeletedMessage, PURGE_REASON_AUTHOR_DELETION, PURGE_TARGET_MESSAGE,
};
use super::super::layout;
use super::super::rows::{
    message_key, message_row, message_tombstone_row, opened_message_row, sealed_message_row,
    MessageRow, OpenedMessageRow, SealedMessageRow, MESSAGE_ROWS, OPENED_MESSAGE_ROWS,
    SEALED_MESSAGE_ROWS,
};
use super::validation::{
    matched_secret_payload, require_fact_scope, validate_deletion_context, validate_signer_context,
};
use crate::protocol::matchers;

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
    let message_offer = matchers::message_offer(fact.id, scope.clone(), fact.id);
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
                    table: OPENED_MESSAGE_ROWS,
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
            .intent(intent::purge_deleted_message_intent(PurgeDeletedMessage {
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
    let secret_payload = matched_secret_payload(context, &secret_need)?;

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

    if let Some(secret_payload) = secret_payload {
        let text = decrypt_text(&message, secret_payload)?;
        return Ok(ProjectionOutput::new()
            .need(signer_need)
            .need(deletion_need)
            .offer(message_offer)
            .intent(sealed_row)
            .intent(
                AtomicIntent::PutRow(message_row(MessageRow {
                    workspace_id: message.workspace_id,
                    message_id: fact.id,
                    created_at_ms: message.created_at_ms,
                    author_user_id: message.author_user_id,
                    signer_id: message.signer_id,
                    minute: message.minute,
                    leaf_id: message.leaf_id,
                }))
                .into_intent(),
            )
            .intent(
                AtomicIntent::PutRow(opened_message_row(OpenedMessageRow {
                    workspace_id: message.workspace_id,
                    message_id: fact.id,
                    created_at_ms: message.created_at_ms,
                    author_user_id: message.author_user_id,
                    signer_id: message.signer_id,
                    text,
                }))
                .into_intent(),
            )
            .intent(share_fact_with_workspace_intent_for_fact(
                message.workspace_id,
                fact,
            )));
    }

    Ok(ProjectionOutput::new()
        .need(signer_need)
        .need(secret_need)
        .need(deletion_need)
        .offer(message_offer)
        .intent(sealed_row)
        .intent(share_fact_with_workspace_intent_for_fact(
            message.workspace_id,
            fact,
        )))
}

fn decrypt_text(message: &SealedMessageFact, secret_payload: &Fact) -> Result<String, String> {
    let key = if let Ok(secret) = encryption::layout::decode_local_key_secret(&secret_payload.bytes)
    {
        if secret.workspace_id != message.workspace_id || secret.frontier_id != message.frontier_id
        {
            return Err("sealed-message root secret does not match message".to_string());
        }
        secret.key_secret
    } else {
        let node = encryption::layout::decode_local_history_node_secret(&secret_payload.bytes)
            .map_err(|_| "sealed-message secret context is not local key material".to_string())?;
        if node.workspace_id != message.workspace_id || node.frontier_id != message.frontier_id {
            return Err("sealed-message history secret does not match message".to_string());
        }
        node.node_secret
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &key,
        &crate::protocol::facts::content::sealed_message::create::associated_data(
            message.workspace_id,
            message.frontier_id,
            message.minute,
        ),
        &message.nonce,
        &message.ciphertext,
    )?;
    crate::protocol::facts::content::sealed_message::create::recover_text(&plaintext)
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

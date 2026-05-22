//! Content-reaction projector.
//!
//! POLICY. A content_reaction is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and contains a raw or signed
//!      reaction payload.
//!   2. CONTEXT. Projection waits for signer, target content message, target
//!      deletion, and author context; deleted targets remove the reaction row.
//!   3. MATERIALIZE. Live reactions write one row and share the fact.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{RowMutation, TableDeleteWhere};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::core::select::Value;

use crate::protocol::facts::content::message::authority::{self, DecodedPayload};
use crate::protocol::facts::content::{message, message_deletion};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::rows::{reaction_row, ReactionRow, REACTION_KEY_COLUMNS, REACTION_ROWS};

#[derive(Debug, Clone, Default)]
pub struct ContentReactionProjector;

impl ContentReactionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentReactionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentReactionProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: authority::DecodedFact<super::fact::ContentReactionFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let authority::DecodedFact {
            payload: reaction,
            signer,
            envelope,
        } = decoded;
        let scope = crate::protocol::facts::identity::workspace::scope(reaction.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context and deletion gates.
        let signer_need = authority::signer_need(fact.id, signer);
        let target_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message",
            scope.clone(),
            reaction.target_message_id,
            reaction.target_message_id,
        );
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "identity_user",
            crate::core::facts::FactScope::Global,
            reaction.author_user_id,
            reaction.author_user_id,
        );
        if let (Some(signer), Some(need)) = (signer, signer_need.as_ref()) {
            if !authority::validate_signer_context(
                context,
                need,
                signer,
                reaction.workspace_id,
                Some(reaction.author_user_id),
                "reaction",
            )? {
                return Ok(output_with_needs([
                    signer_need,
                    Some(target_need),
                    Some(author_need),
                    None,
                ]));
            }
        }
        let Some(target) = context_payload(context, &target_need, "reaction target")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
                None,
            ]));
        };
        let target_context = target_message_context(
            target,
            &scope,
            reaction.workspace_id,
            reaction.target_message_id,
            "reaction target",
        )?;
        let target_deletion_need = crate::core::context::ContextNeed::for_key_parts(
            fact.id,
            "content_deleted",
            scope.clone(),
            [
                &reaction.target_message_id,
                &target_context.message.author_user_id,
            ],
        )?;
        if let Some(deletion) =
            context_payload(context, &target_deletion_need, "reaction target deletion")?
        {
            validate_message_deletion(
                deletion,
                reaction.workspace_id,
                reaction.target_message_id,
                target_context.message.author_user_id,
            )?;
            authority::verify_envelope(envelope.as_ref(), "reaction")?;
            return Ok(delete_reaction_projection(reaction.workspace_id, fact.id)
                .need(target_need)
                .need(target_deletion_need));
        }
        let Some(author) = context_payload(context, &author_need, "reaction author")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(target_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, reaction.workspace_id, reaction.author_user_id)?;
        authority::verify_envelope(envelope.as_ref(), "reaction")?;

        // 3. Materialize.
        let row = reaction_row(ReactionRow {
            workspace_id: reaction.workspace_id,
            reaction_id: fact.id,
            created_at_ms: reaction.created_at_ms,
            target_message_id: reaction.target_message_id,
            author_user_id: reaction.author_user_id,
            nonce: reaction.nonce,
            ciphertext: reaction.ciphertext,
        })?;
        Ok(output_with_needs([
            signer_need,
            Some(target_need),
            Some(target_deletion_need),
            Some(author_need),
        ])
        .row_mutation(RowMutation::InsertValues(row))
        .intent(share_fact_with_workspace_intent_for_fact(
            reaction.workspace_id,
            fact,
        )))
    }
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    authority::context_payload(context, need, label)
}

fn output_with_needs(
    needs: impl IntoIterator<Item = Option<crate::core::context::ContextNeed>>,
) -> ProjectionOutput {
    needs
        .into_iter()
        .flatten()
        .fold(ProjectionOutput::new(), |output, need| output.need(need))
}

fn target_message_context<'a>(
    payload: &'a Fact,
    expected_scope: &FactScope,
    workspace_id: crate::core::facts::FactId,
    target_message_id: crate::core::facts::FactId,
    label: &str,
) -> Result<TargetMessageContext<'a>, String> {
    if payload.id != target_message_id {
        return Err("reaction target context payload id mismatch".to_string());
    }
    if &payload.scope != expected_scope {
        return Err("reaction target context scope does not match reaction workspace".to_string());
    }
    let target = decode_target_message_payload(payload, label)?;
    if target.workspace_id != workspace_id {
        return Err("reaction target message workspace does not match reaction".to_string());
    }
    Ok(TargetMessageContext {
        _payload: payload,
        message: target,
    })
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("reaction author context payload id mismatch".to_string());
    }
    let author_payload = maybe_signed_payload(payload, user::TYPE_USER, "reaction author")?;
    let author =
        crate::protocol::facts::identity::user::decode_fact_payload(&author_payload.payload)
            .map_err(|_| "reaction author context is not an identity user".to_string())?;
    if author.workspace_id != workspace_id {
        return Err("reaction author workspace does not match reaction".to_string());
    }
    Ok(())
}

fn delete_reaction_projection(workspace_id: FactId, reaction_id: FactId) -> ProjectionOutput {
    ProjectionOutput::new().row_mutation(RowMutation::DeleteWhere(reaction_delete(
        workspace_id,
        reaction_id,
    )))
}

fn reaction_delete(workspace_id: FactId, reaction_id: FactId) -> TableDeleteWhere {
    TableDeleteWhere {
        table: REACTION_ROWS,
        columns: REACTION_KEY_COLUMNS,
        values: vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::Bytes(reaction_id.to_vec()),
        ],
    }
}

fn validate_message_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion_payload = maybe_signed_payload(
        payload,
        message_deletion::TYPE_CONTENT_MESSAGE_DELETION,
        "target deletion",
    )?;
    let deletion = message_deletion::decode_fact_payload(&deletion_payload.payload)
        .map_err(|_| "target deletion context is not a content message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("target deletion workspace does not match reaction".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("target deletion target does not match reaction parent".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("target deletion author does not match target message author".to_string());
    }
    Ok(())
}

struct TargetMessageContext<'a> {
    _payload: &'a Fact,
    message: TargetMessage,
}

struct TargetMessage {
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
}

fn decode_target_message_payload(payload: &Fact, label: &str) -> Result<TargetMessage, String> {
    let message_payload = maybe_signed_payload(payload, message::TYPE_CONTENT_MESSAGE, label)?;
    let message = message::decode_fact_payload(&message_payload.payload)
        .map_err(|_| format!("{label} context is not a content message"))?;
    Ok(TargetMessage {
        workspace_id: message.workspace_id,
        author_user_id: message.author_user_id,
    })
}

fn maybe_signed_payload(
    payload: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if payload.bytes.first().copied() == Some(identity::signed_fact::TYPE_SIGNED_FACT) {
        authority::decode_raw_or_signed(payload, expected_type, label)
    } else {
        Ok(DecodedPayload {
            payload: payload.bytes.clone(),
            signer: None,
            envelope: None,
        })
    }
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content reaction fact scope does not match body workspace".to_string())
    }
}

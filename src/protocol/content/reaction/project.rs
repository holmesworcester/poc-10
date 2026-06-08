//! Content-reaction projector.
//!
//! POLICY. A content_reaction is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped, signed, and contains a
//!      reaction payload.
//!   2. CONTEXT. Projection waits for signer, target content message, target
//!      deletion, and author context; deleted targets remove the reaction row
//!      and purge this reaction fact.
//!   3. MATERIALIZE. Live reactions write one row and share the fact.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::Value;
use crate::core::intents::{RowMutation, TableDeleteWhere, TableInsert};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

use crate::protocol::auth::signature;
use crate::protocol::content::message::project::{self, FactSigner};
use crate::protocol::content::{message, message_deletion};
use crate::protocol::registry::read_models;
use crate::protocol::sync::shared_fact::project::{
    context_have_from_optional_needs, retract_fact_from_sync, share_fact_with_sync,
};

use super::fact::REACTION_CIPHERTEXT_BYTES;
use super::queries::ReactionRow;
use super::REACTION_ROWS;

pub(crate) const REACTION_KEY_COLUMNS: &[&str] = read_models::CONTENT_REACTIONS.key_columns;

pub fn reaction_row(input: ReactionRow) -> Result<TableInsert, String> {
    if input.ciphertext.len() > REACTION_CIPHERTEXT_BYTES {
        return Err("reaction row ciphertext exceeds fixed slot".to_string());
    }
    Ok(read_models::CONTENT_REACTIONS.insert(vec![
        Value::Bytes(input.workspace_id.to_vec()),
        Value::Bytes(input.reaction_id.to_vec()),
        Value::Bytes(input.target_message_id.to_vec()),
        Value::Bytes(input.author_user_id.to_vec()),
        Value::U64(input.created_at_ms),
        Value::Bytes(input.nonce.to_vec()),
        Value::Bytes(input.ciphertext),
        Value::Bool(false),
    ]))
}

/// Staged read pipeline for the reaction fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "content::reaction::Codec",
    authenticate: "content::reaction::authenticate::ContentReactionAuthenticator",
    adapt: "content::reaction::adapt::ContentReactionAdapter",
    project: "content::reaction::project::ContentReactionProjector",
};

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
        project_staged::<
            super::Codec,
            super::authenticate::ContentReactionAuthenticator,
            super::adapt::ContentReactionAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::ContentReactionFact> for ContentReactionProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        reaction: super::fact::ContentReactionFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(reaction.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context, signature evidence, and deletion gates.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            reaction.signer_public_key,
        )?;
        let signer_need = project::signer_need(fact.id, reaction.workspace_id, reaction.signer_id);
        let target_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message",
            scope.clone(),
            reaction.target_message_id,
            reaction.target_message_id,
        );
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
            reaction.author_user_id,
            reaction.author_user_id,
        );
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            reaction.workspace_id,
            fact.id,
            reaction.signer_public_key,
            "reaction",
        )? {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
            ]));
        }
        if !project::validate_signer_context(
            context,
            &signer_need,
            FactSigner {
                signer_id: reaction.signer_id,
                signer_public_key: reaction.signer_public_key,
            },
            reaction.workspace_id,
            Some(reaction.author_user_id),
            "reaction",
        )? {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(author_need),
                None,
            ]));
        }
        let Some(target) = context_payload(context, &target_need, "reaction target")? else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
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
        let target_deletion_need = crate::core::pipeline::fact_purged_need(
            fact.id,
            scope.clone(),
            project::fact_purged_key(
                target_context.message.frontier_id,
                target_context.message.minute,
                reaction.target_message_id,
            ),
        );
        if let Some(deletion) =
            context_payload(context, &target_deletion_need, "reaction target deletion")?
        {
            validate_message_deletion(
                deletion,
                reaction.workspace_id,
                target_context.message.frontier_id,
                target_context.message.minute,
                reaction.target_message_id,
                target_context.message.author_user_id,
            )?;
            return Ok(retract_fact_from_sync(
                delete_reaction_projection(reaction.workspace_id, fact.id)
                    .need(signature_need)
                    .need(target_need)
                    .need(target_deletion_need)
                    .purge_self(fact.id),
                reaction.workspace_id,
                fact.id,
                reaction.created_at_ms,
            ));
        }
        let Some(author) = context_payload(context, &author_need, "reaction author")? else {
            return Ok(output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(target_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, reaction.workspace_id, reaction.author_user_id)?;
        let context_have = context_have_from_optional_needs(
            context,
            [
                Some(&signature_need),
                Some(&signer_need),
                Some(&target_need),
                Some(&target_deletion_need),
                Some(&author_need),
            ],
        );

        // 3. Materialize.
        let row = reaction_row(ReactionRow {
            workspace_id: reaction.workspace_id,
            reaction_id: fact.id,
            created_at_ms: reaction.created_at_ms,
            target_message_id: reaction.target_message_id,
            author_user_id: reaction.author_user_id,
            nonce: reaction.nonce,
            ciphertext: reaction.ciphertext.bytes().to_vec(),
        })?;
        Ok(share_fact_with_sync(
            output_with_needs([
                Some(signature_need),
                Some(signer_need),
                Some(target_need),
                Some(target_deletion_need),
                Some(author_need),
            ])
            .row_mutation(RowMutation::InsertValues(row)),
            reaction.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    project::context_payload(context, need, label)
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
    let author = crate::protocol::auth::user::decode_fact_payload(payload.body())
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
    target_frontier_id: crate::core::facts::FactId,
    target_minute: u64,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion = message_deletion::decode_fact_payload(payload.body())
        .map_err(|_| "target deletion context is not a content message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("target deletion workspace does not match reaction".to_string());
    }
    if deletion.target_frontier_id != target_frontier_id {
        return Err("target deletion frontier does not match reaction parent".to_string());
    }
    if deletion.target_minute != target_minute {
        return Err("target deletion minute does not match reaction parent".to_string());
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
    frontier_id: crate::core::facts::FactId,
    minute: u64,
    author_user_id: crate::core::facts::FactId,
}

fn decode_target_message_payload(payload: &Fact, label: &str) -> Result<TargetMessage, String> {
    let message = project::decode_typed_fact(
        payload,
        message::TYPE_CONTENT_MESSAGE,
        label,
        message::decode_fact_payload,
    )
    .map_err(|_| format!("{label} context is not a content message"))?;
    Ok(TargetMessage {
        workspace_id: message.workspace_id,
        frontier_id: message.frontier_id,
        minute: message.minute,
        author_user_id: message.author_user_id,
    })
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content reaction fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::content::reaction::fact::REACTION_NONCE_BYTES;

    const REACTION_COLUMNS: &[&str] = read_models::CONTENT_REACTIONS.columns;

    #[test]
    fn reaction_row_round_trips_workspace_keyed_value() {
        let input = ReactionRow {
            workspace_id: [1; 32],
            reaction_id: [2; 32],
            created_at_ms: 5_000,
            target_message_id: [3; 32],
            author_user_id: [4; 32],
            nonce: [5; REACTION_NONCE_BYTES],
            ciphertext: b"r".to_vec(),
        };
        let row = reaction_row(input).expect("row");
        assert_eq!(row.table, REACTION_ROWS);
        assert_eq!(row.columns, REACTION_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[2], Value::Bytes(vec![3; 32]));
        assert_eq!(row.values[3], Value::Bytes(vec![4; 32]));
        assert_eq!(row.values[5], Value::Bytes(vec![5; REACTION_NONCE_BYTES]));
        assert_eq!(row.values[6], Value::Bytes(b"r".to_vec()));
        assert_eq!(row.values[7], Value::Bool(false));
    }
}

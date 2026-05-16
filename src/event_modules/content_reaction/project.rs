//! Poc-10 content-reaction projector.
//!
//! Decodes a content-reaction fact, waits for the target message when needed,
//! and emits a single `PutRow` into `reaction_rows` only after the target
//! message context is matched and validated. The reaction id used in the row
//! key is the fact id.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Legacy validates a signed envelope around the payload; the target
//!   signed-fact envelope is a separate event module.
//! - Legacy admit-check drops reactions whose parent message is already
//!   tombstoned. That cascade depends on the message tombstone projection and
//!   is handled outside this row projector.
//! - Legacy derives a deterministic leaf coordinate from author+target+
//!   frontier+ts so duplicate reactions collapse on admission. The target
//!   per-message FS isn't ported yet, so this slice keys rows by fact id.
//! - Legacy decrypts the emoji into a plaintext `content.reactions` row;
//!   per-message decryption secrets aren't surfaced in this slice.

use crate::core::facts::Fact;
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_message::{
    layout as message_layout, matchers as message_matchers,
};

use super::layout;
use super::rows::{reaction_key, reaction_row, ReactionRow, REACTION_ROWS};

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
        let reaction = layout::decode_fact(&fact.bytes)?;
        let scope = message_matchers::workspace_scope(reaction.workspace_id);
        require_fact_scope(fact, &scope)?;
        let reaction_deletion_need = message_matchers::deletion_need(
            fact.id,
            scope.clone(),
            fact.id,
            reaction.author_user_id,
        );
        if let Some(deletion) = context.payload_for(&reaction_deletion_need) {
            validate_reaction_deletion(
                deletion,
                reaction.workspace_id,
                fact.id,
                reaction.author_user_id,
            )?;
            return Ok(delete_reaction_projection(reaction.workspace_id, fact.id));
        }
        let target_need =
            message_matchers::message_need(fact.id, scope.clone(), reaction.target_message_id);
        let Some(target) = context.payload_for(&target_need) else {
            return Ok(ProjectionOutput::new()
                .need(target_need)
                .need(reaction_deletion_need));
        };
        let target_message = message_layout::decode_fact(&target.bytes)
            .map_err(|_| "reaction target context is not a content message".to_string())?;
        if target_message.workspace_id != reaction.workspace_id {
            return Err("reaction target message workspace does not match reaction".to_string());
        }
        let target_deletion_need = message_matchers::deletion_need(
            fact.id,
            scope,
            reaction.target_message_id,
            target_message.author_user_id,
        );
        if let Some(deletion) = context.payload_for(&target_deletion_need) {
            validate_message_deletion(
                deletion,
                reaction.workspace_id,
                reaction.target_message_id,
                target_message.author_user_id,
            )?;
            return Ok(delete_reaction_projection(reaction.workspace_id, fact.id));
        }

        let row = reaction_row(ReactionRow {
            workspace_id: reaction.workspace_id,
            reaction_id: fact.id,
            created_at_ms: reaction.created_at_ms,
            target_message_id: reaction.target_message_id,
            author_user_id: reaction.author_user_id,
            nonce: reaction.nonce,
            ciphertext: reaction.ciphertext,
        })?;
        Ok(ProjectionOutput::new()
            .need(reaction_deletion_need)
            .need(target_deletion_need)
            .intent(AtomicIntent::PutRow(row).into_intent()))
    }
}

fn delete_reaction_projection(
    workspace_id: crate::core::facts::FactId,
    reaction_id: crate::core::facts::FactId,
) -> ProjectionOutput {
    ProjectionOutput::new().intent(
        AtomicIntent::DeleteRow(TableDelete {
            table: REACTION_ROWS,
            key: reaction_key(workspace_id, reaction_id),
        })
        .into_intent(),
    )
}

fn validate_reaction_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_reaction_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    // TODO(content): introduce a dedicated content-reaction deletion fact. The
    // current target tree has message/file deletion facts only, so this accepts
    // the shared content-deleted role via the file-deletion layout as a narrow
    // local placeholder for direct reaction deletion.
    let deletion = crate::event_modules::content_file_deletion::layout::decode_fact(&payload.bytes)
        .map_err(|_| "reaction deletion context is not a content deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("reaction deletion workspace does not match reaction".to_string());
    }
    if deletion.target_file_id != target_reaction_id {
        return Err("reaction deletion target does not match reaction".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("reaction deletion author does not match reaction author".to_string());
    }
    Ok(())
}

fn validate_message_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion =
        crate::event_modules::content_message_deletion::layout::decode_fact(&payload.bytes)
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

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content reaction fact scope does not match body workspace".to_string())
    }
}

//! Poc-10 content-message-deletion projector.
//!
//! Decodes a deletion fact, waits for the target message and named author as
//! matched context, then emits a `PutRow` into `message_deletion_rows`.
//!
//! Poc-8 only authorizes message deletion when the deletion author is the
//! target message author. There is no admin/moderator delete path in poc-8.
//! The signed endpoint binding is handled by the signed-fact/identity slices;
//! this projector enforces the target-message authorization that belongs to
//! deletion semantics.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_message::{
    layout as message_layout, matchers as message_matchers,
};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;

use super::layout;
use super::rows::{message_deletion_row, MessageDeletionRow};

#[derive(Debug, Clone, Default)]
pub struct ContentMessageDeletionProjector;

impl ContentMessageDeletionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentMessageDeletionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let deletion = layout::decode_fact(&fact.bytes)?;
        let scope = message_matchers::workspace_scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;
        let target_need =
            message_matchers::message_need(fact.id, scope.clone(), deletion.target_message_id);
        let author_need = identity_matchers::exact_need(
            fact.id,
            identity_matchers::user_role(),
            deletion.author_user_id,
        );
        let Some(target_fact) = context.payload_for(&target_need) else {
            return Ok(ProjectionOutput::new().need(target_need).need(author_need));
        };
        let Some(author_fact) = context.payload_for(&author_need) else {
            return Ok(ProjectionOutput::new().need(target_need).need(author_need));
        };
        validate_target_message(&deletion, target_fact)?;
        validate_author_user(&deletion, author_fact)?;
        let row = message_deletion_row(MessageDeletionRow {
            workspace_id: deletion.workspace_id,
            target_message_id: deletion.target_message_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        })?;
        Ok(ProjectionOutput::new()
            .offer(message_matchers::deletion_offer(
                fact.id,
                scope,
                deletion.target_message_id,
                deletion.author_user_id,
            ))
            .intent(AtomicIntent::PutRow(row).into_intent()))
    }
}

fn validate_target_message(
    deletion: &super::fact::ContentMessageDeletionFact,
    target_fact: &Fact,
) -> Result<(), String> {
    if target_fact.id != deletion.target_message_id {
        return Err("message deletion target context payload id mismatch".to_string());
    }
    let target = message_layout::decode_fact(&target_fact.bytes)
        .map_err(|_| "message deletion target context must be a content message".to_string())?;
    if target.workspace_id != deletion.workspace_id {
        return Err("message deletion target workspace does not match deletion".to_string());
    }
    if target.author_user_id != deletion.author_user_id {
        return Err("message deletion author is not the target message author".to_string());
    }
    Ok(())
}

fn validate_author_user(
    deletion: &super::fact::ContentMessageDeletionFact,
    author_fact: &Fact,
) -> Result<(), String> {
    if author_fact.id != deletion.author_user_id {
        return Err("message deletion author context payload id mismatch".to_string());
    }
    let author = user_layout::decode_fact(&author_fact.bytes)
        .map_err(|_| "message deletion author context must be an identity user".to_string())?;
    if author.workspace_id != deletion.workspace_id {
        return Err("message deletion author workspace does not match deletion".to_string());
    }
    Ok(())
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content message deletion fact scope does not match body workspace".to_string())
    }
}

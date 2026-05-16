//! Poc-10 content-message projector.
//!
//! Decodes a content-message fact and emits a single `PutRow` into
//! `content_message_rows`. The message id used in the row key is the fact id.
//!
//! Parity gaps (intentional, deferred to later slices):
//!  - Legacy validates a signed envelope, a workspace-membership chain for the
//!    signer endpoint, and an author dependency on a signed user event. The
//!    target signed-fact and identity modules are wired in separate slices.
//!  - Legacy binds the message to a per-message leaf event dependency and
//!    recomputes the deterministic leaf coordinate from canonical fields.
//!    The target leaf module isn't surfaced here; the projector trusts the
//!    `leaf_id`/`minute` hints inside the fact.
//!  - Legacy resolves the referenced disappearing-messages setting and
//!    rejects `expires_at_minute` mismatches; the setting module is not
//!    ported.
//!  - Legacy writes tombstone rows on self-deletion labels; the deletion
//!    projector is a separate event module.

use crate::core::facts::Fact;
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::matchers;
use super::rows::{content_message_key, content_message_row, CONTENT_MESSAGE_ROWS};

#[derive(Debug, Clone, Default)]
pub struct ContentMessageProjector;

impl ContentMessageProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentMessageProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let message = layout::decode_fact(&fact.bytes)?;
        let scope = matchers::workspace_scope(message.workspace_id);
        require_fact_scope(fact, &scope)?;
        let deletion_need =
            matchers::deletion_need(fact.id, scope.clone(), fact.id, message.author_user_id);
        if let Some(deletion) = context.payload_for(&deletion_need) {
            validate_message_deletion(
                deletion,
                message.workspace_id,
                fact.id,
                message.author_user_id,
            )?;
            return Ok(ProjectionOutput::new().intent(
                AtomicIntent::DeleteRow(TableDelete {
                    table: CONTENT_MESSAGE_ROWS,
                    key: content_message_key(message.workspace_id, fact.id),
                })
                .into_intent(),
            ));
        }
        let row = content_message_row(fact.id, &message);
        Ok(ProjectionOutput::new()
            .need(deletion_need)
            .offer(matchers::message_offer(fact.id, scope, fact.id))
            .intent(AtomicIntent::PutRow(row).into_intent()))
    }
}

fn validate_message_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion =
        crate::event_modules::content_message_deletion::layout::decode_fact(&payload.bytes)
            .map_err(|_| {
                "message deletion context is not a content message deletion".to_string()
            })?;
    if deletion.workspace_id != workspace_id {
        return Err("message deletion workspace does not match message".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("message deletion target does not match message".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("message deletion author does not match message author".to_string());
    }
    Ok(())
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content message fact scope does not match body workspace".to_string())
    }
}

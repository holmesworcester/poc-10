//! Poc-10 content-file-deletion projector.
//!
//! POLICY. A content_file_deletion is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped, signed, and contains a
//!      deletion payload for one target file and author user.
//!   2. AUTHORITY. The signer, target file, and author user contexts must all
//!      validate against the same workspace and target.
//!   3. MATERIALIZE. Once authorized, write the deletion row, publish the
//!      content_purged offer, and share the deletion fact.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::auth;
use crate::protocol::auth::user;
use crate::protocol::content::message::fact::unix_minute_for;
use crate::protocol::content::message::project::{self, DecodedPayload};
use crate::protocol::content::{file, message, purge::project as content_purge};
use crate::protocol::sync::shared_fact::project::{
    context_have_from_optional_needs, share_fact_with_sync,
};

use super::rows::{file_deletion_row, FileDeletionRow};

#[derive(Debug, Clone, Default)]
pub struct ContentFileDeletionProjector;

impl ContentFileDeletionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileDeletionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentFileDeletionProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: project::DecodedFact<super::fact::ContentFileDeletionFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let project::DecodedFact {
            payload: deletion,
            signer,
            envelope,
        } = decoded;
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority.
        let signer_need = project::signer_need(fact.id, deletion.workspace_id, signer);
        let target_need = crate::core::context::ContextNeed::range(
            fact.id,
            "sync_exact_fact",
            scope.clone(),
            deletion.target_file_id,
            deletion.target_file_id,
        );
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
            deletion.author_user_id,
            deletion.author_user_id,
        );
        if let (Some(signer), Some(need)) = (signer, signer_need.as_ref()) {
            if !project::validate_signer_context(
                context,
                need,
                signer,
                deletion.workspace_id,
                Some(deletion.author_user_id),
                "file deletion",
            )? {
                return Ok(output_with_needs([
                    signer_need,
                    Some(target_need),
                    Some(author_need),
                ]));
            }
        }
        let Some(target_fact) = context_payload(context, &target_need, "file deletion target")?
        else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
            ]));
        };
        let target = validate_target_file(&deletion, target_fact, &scope)?;
        let parent_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message",
            scope.clone(),
            target.message_id,
            target.message_id,
        );
        let Some(parent_fact) =
            context_payload(context, &parent_need, "file deletion parent message")?
        else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(parent_need),
                Some(author_need),
            ]));
        };
        let parent = validate_parent_message(&target, parent_fact, &scope)?;
        let Some(author_fact) = context_payload(context, &author_need, "file deletion author")?
        else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(parent_need),
                Some(author_need),
            ]));
        };
        validate_author_user(&deletion, author_fact)?;
        project::verify_envelope(envelope.as_ref(), "file deletion")?;
        let context_have = context_have_from_optional_needs(
            context,
            [
                signer_need.as_ref(),
                Some(&target_need),
                Some(&parent_need),
                Some(&author_need),
            ],
        );

        // 3. Materialize.
        let row = file_deletion_row(FileDeletionRow {
            workspace_id: deletion.workspace_id,
            target_file_id: deletion.target_file_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        });
        Ok(share_fact_with_sync(
            output_with_needs([
                signer_need,
                Some(target_need),
                Some(parent_need),
                Some(author_need),
            ])
            .offer(content_purge::target_purged_offer(
                fact.id,
                scope,
                parent.frontier_id,
                unix_minute_for(target.created_at_ms),
                deletion.target_file_id,
            ))
            .row_mutation(RowMutation::InsertValues(row)),
            deletion.workspace_id,
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

fn validate_target_file(
    deletion: &super::fact::ContentFileDeletionFact,
    target_fact: &Fact,
    expected_scope: &FactScope,
) -> Result<file::fact::ContentFileFact, String> {
    if target_fact.id != deletion.target_file_id {
        return Err("file deletion target context payload id mismatch".to_string());
    }
    if &target_fact.scope != expected_scope {
        return Err("file deletion target scope does not match deletion".to_string());
    }
    let target_payload = project::decode_signed_payload(
        target_fact,
        file::TYPE_CONTENT_FILE,
        "file deletion target",
    )?;
    let target = file::decode_fact_payload(&target_payload.payload)
        .map_err(|_| "file deletion target context must be a content file".to_string())?;
    if target.workspace_id != deletion.workspace_id {
        return Err("file deletion target workspace does not match deletion".to_string());
    }
    if target.author_user_id != deletion.author_user_id {
        return Err("file deletion author is not the target file author".to_string());
    }
    Ok(target)
}

fn validate_parent_message(
    target: &file::fact::ContentFileFact,
    parent_fact: &Fact,
    expected_scope: &FactScope,
) -> Result<message::fact::ContentMessageFact, String> {
    if parent_fact.id != target.message_id {
        return Err("file deletion parent context payload id mismatch".to_string());
    }
    if &parent_fact.scope != expected_scope {
        return Err("file deletion parent scope does not match deletion".to_string());
    }
    let parent_payload = project::decode_signed_payload(
        parent_fact,
        message::TYPE_CONTENT_MESSAGE,
        "file deletion parent",
    )?;
    let parent = message::decode_fact_payload(&parent_payload.payload)
        .map_err(|_| "file deletion parent context must be a content message".to_string())?;
    if parent.workspace_id != target.workspace_id {
        return Err("file deletion parent workspace does not match file".to_string());
    }
    Ok(parent)
}

fn validate_author_user(
    deletion: &super::fact::ContentFileDeletionFact,
    author_fact: &Fact,
) -> Result<(), String> {
    if author_fact.id != deletion.author_user_id {
        return Err("file deletion author context payload id mismatch".to_string());
    }
    let author_payload =
        decode_context_payload(author_fact, user::TYPE_USER, "file deletion author")?;
    let author = user::decode_fact_payload(&author_payload.payload)
        .map_err(|_| "file deletion author context must be an identity user".to_string())?;
    if author.workspace_id != deletion.workspace_id {
        return Err("file deletion author workspace does not match deletion".to_string());
    }
    Ok(())
}

fn decode_context_payload(
    payload: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if payload.bytes.first().copied() == Some(auth::signed_fact::TYPE_SIGNED_FACT) {
        project::decode_signed_payload(payload, expected_type, label)
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
        Err("content file deletion fact scope does not match body workspace".to_string())
    }
}

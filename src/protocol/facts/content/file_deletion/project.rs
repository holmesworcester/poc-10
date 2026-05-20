//! Poc-10 content-file-deletion projector.
//!
//! POLICY. A content_file_deletion is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and contains a raw or signed
//!      deletion payload for one target file and author user.
//!   2. AUTHORITY. The signer, target file, and author user contexts must all
//!      validate against the same workspace and target.
//!   3. MATERIALIZE. Once authorized, write the deletion row, publish the
//!      content_deleted offer, and share the deletion fact.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::facts::content::file;
use crate::protocol::facts::content::message::authority::{self, DecodedPayload};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

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
        decoded: authority::DecodedFact<super::fact::ContentFileDeletionFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let authority::DecodedFact {
            payload: deletion,
            signer,
            envelope,
        } = decoded;
        let scope = matchers::workspace_scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority.
        let signer_need = authority::signer_need(fact.id, signer);
        let target_need = crate::protocol::matchers::exact_fact_need(
            fact.id,
            scope.clone(),
            deletion.target_file_id,
        );
        let author_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::user_role(),
            deletion.author_user_id,
        );
        if let (Some(signer), Some(need)) = (signer, signer_need.as_ref()) {
            if !authority::validate_signer_context(
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
        let Some(author_fact) = context_payload(context, &author_need, "file deletion author")?
        else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
            ]));
        };
        validate_target_file(&deletion, target_fact, &scope)?;
        validate_author_user(&deletion, author_fact)?;
        authority::verify_envelope(envelope.as_ref(), "file deletion")?;

        // 3. Materialize.
        let row = file_deletion_row(FileDeletionRow {
            workspace_id: deletion.workspace_id,
            target_file_id: deletion.target_file_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        })?;
        Ok(
            output_with_needs([signer_need, Some(target_need), Some(author_need)])
                .offer(matchers::deletion_offer(
                    fact.id,
                    scope,
                    deletion.target_file_id,
                    deletion.author_user_id,
                ))
                .intent(AtomicIntent::PutRow(row).into_intent())
                .intent(share_fact_with_workspace_intent_for_fact(
                    deletion.workspace_id,
                    fact,
                )),
        )
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

fn validate_target_file(
    deletion: &super::fact::ContentFileDeletionFact,
    target_fact: &Fact,
    expected_scope: &FactScope,
) -> Result<(), String> {
    if target_fact.id != deletion.target_file_id {
        return Err("file deletion target context payload id mismatch".to_string());
    }
    if &target_fact.scope != expected_scope {
        return Err("file deletion target scope does not match deletion".to_string());
    }
    let target_payload =
        maybe_signed_payload(target_fact, file::TYPE_CONTENT_FILE, "file deletion target")?;
    let target = file::decode_fact_payload(&target_payload.payload)
        .map_err(|_| "file deletion target context must be a content file".to_string())?;
    if target.workspace_id != deletion.workspace_id {
        return Err("file deletion target workspace does not match deletion".to_string());
    }
    if target.author_user_id != deletion.author_user_id {
        return Err("file deletion author is not the target file author".to_string());
    }
    Ok(())
}

fn validate_author_user(
    deletion: &super::fact::ContentFileDeletionFact,
    author_fact: &Fact,
) -> Result<(), String> {
    if author_fact.id != deletion.author_user_id {
        return Err("file deletion author context payload id mismatch".to_string());
    }
    let author_payload =
        maybe_signed_payload(author_fact, user::TYPE_USER, "file deletion author")?;
    let author = user::decode_fact_payload(&author_payload.payload)
        .map_err(|_| "file deletion author context must be an identity user".to_string())?;
    if author.workspace_id != deletion.workspace_id {
        return Err("file deletion author workspace does not match deletion".to_string());
    }
    Ok(())
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
        Err("content file deletion fact scope does not match body workspace".to_string())
    }
}

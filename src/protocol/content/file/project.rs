//! Content-file projector.
//!
//! POLICY. A content_file is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped, has valid descriptor fields,
//!      and contains a raw or signed content_file payload.
//!   2. CONTEXT. Projection waits for signer, parent content message, deletion,
//!      parent deletion, and author context; deletion context removes the
//!      descriptor row and purges this file fact.
//!   3. MATERIALIZE. Live files publish file/exact-fact offers, write the
//!      descriptor row, and share the fact. File bytes remain slice facts.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::Value;
use crate::core::intents::{RowMutation, TableDeleteWhere};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::auth;
use crate::protocol::auth::user;
use crate::protocol::content::message::project::{self, DecodedPayload};
use crate::protocol::content::{
    file_deletion, message, message_deletion, purge::project as content_purge,
};
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::fact::MAX_FILE_BYTES;
use super::rows::{content_file_row, FILE_KEY_COLUMNS, FILE_ROWS};

#[derive(Debug, Clone, Default)]
pub struct ContentFileProjector;

impl ContentFileProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentFileProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: project::DecodedFact<super::fact::ContentFileFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let project::DecodedFact {
            payload: file,
            signer,
            envelope,
        } = decoded;
        validate_file_fields(&file)?;
        let scope = crate::protocol::auth::workspace::scope(file.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context and deletion gates.
        let signer_need = project::signer_need(fact.id, signer);
        let parent_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message",
            scope.clone(),
            file.message_id,
            file.message_id,
        );
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
            file.author_user_id,
            file.author_user_id,
        );
        if let (Some(signer), Some(need)) = (signer, signer_need.as_ref()) {
            if !project::validate_signer_context(
                context,
                need,
                signer,
                file.workspace_id,
                Some(file.author_user_id),
                "file",
            )? {
                return Ok(output_with_needs([
                    signer_need,
                    Some(parent_need),
                    Some(author_need),
                    None,
                ]));
            }
        }
        let Some(parent_payload) = context_payload(context, &parent_need, "file parent")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(parent_need),
                Some(author_need),
            ]));
        };
        let parent = parent_message_context(
            parent_payload,
            &scope,
            file.workspace_id,
            file.message_id,
            "file parent",
        )?;
        let file_deletion_need = content_purge::target_purged_need(
            fact.id,
            scope.clone(),
            parent.message.frontier_id,
            message::fact::unix_minute_for(file.created_at_ms),
            fact.id,
        );
        let parent_deletion_need = content_purge::target_purged_need(
            fact.id,
            scope.clone(),
            parent.message.frontier_id,
            parent.message.minute,
            file.message_id,
        );
        if let Some(deletion) = context_payload(context, &file_deletion_need, "file deletion")? {
            validate_file_deletion(deletion, file.workspace_id, fact.id, file.author_user_id)?;
            project::verify_envelope(envelope.as_ref(), "file")?;
            return Ok(delete_file_projection(file.workspace_id, fact.id)
                .need(parent_need)
                .need(file_deletion_need)
                .need(parent_deletion_need)
                .purge_self(fact.id));
        }
        if let Some(deletion) =
            context_payload(context, &parent_deletion_need, "file parent deletion")?
        {
            validate_message_deletion(
                deletion,
                file.workspace_id,
                parent.message.frontier_id,
                parent.message.minute,
                file.message_id,
                parent.message.author_user_id,
            )?;
            project::verify_envelope(envelope.as_ref(), "file")?;
            return Ok(delete_file_projection(file.workspace_id, fact.id)
                .need(file_deletion_need)
                .need(parent_need)
                .need(parent_deletion_need)
                .purge_self(fact.id));
        }
        let Some(author) = context_payload(context, &author_need, "file author")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(file_deletion_need),
                Some(parent_need),
                Some(parent_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, file.workspace_id, file.author_user_id)?;
        project::verify_envelope(envelope.as_ref(), "file")?;

        // 3. Materialize.
        Ok(output_with_needs([
            signer_need,
            Some(file_deletion_need),
            Some(parent_need),
            Some(parent_deletion_need),
            Some(author_need),
        ])
        .offer(crate::core::context::ContextOffer::range(
            fact.id,
            "content_file",
            scope,
            file.file_id,
            file.file_id,
        ))
        .offer(crate::core::context::ContextOffer::range(
            fact.id,
            "sync_exact_fact",
            crate::protocol::auth::workspace::scope(file.workspace_id),
            fact.id,
            fact.id,
        ))
        .row_mutation(RowMutation::InsertValues(content_file_row(fact.id, &file)))
        .intent(share_fact_with_workspace_intent_for_fact(
            file.workspace_id,
            fact,
        )))
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

fn delete_file_projection(workspace_id: FactId, file_fact_id: FactId) -> ProjectionOutput {
    ProjectionOutput::new().row_mutation(RowMutation::DeleteWhere(content_file_delete(
        workspace_id,
        file_fact_id,
    )))
}

fn content_file_delete(workspace_id: FactId, file_fact_id: FactId) -> TableDeleteWhere {
    TableDeleteWhere {
        table: FILE_ROWS,
        columns: FILE_KEY_COLUMNS,
        values: vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::Bytes(file_fact_id.to_vec()),
        ],
    }
}

fn validate_file_fields(file: &super::fact::ContentFileFact) -> Result<(), String> {
    validate_id("file workspace_id", &file.workspace_id)?;
    validate_id("file message_id", &file.message_id)?;
    validate_id("file author_user_id", &file.author_user_id)?;
    validate_id("file file_id", &file.file_id)?;
    if file.blob_bytes > MAX_FILE_BYTES {
        return Err("file size exceeds the 10 GiB limit".to_string());
    }
    if file.blob_bytes == 0 {
        if file.total_slices != 0 {
            return Err("zero-byte file must declare zero slices".to_string());
        }
        return Ok(());
    }
    if file.total_slices == 0 {
        return Err("non-empty file must declare at least one slice".to_string());
    }
    if file.slice_bytes == 0 {
        return Err("non-empty file must declare a slice budget".to_string());
    }
    let expected: u32 = file
        .blob_bytes
        .div_ceil(file.slice_bytes as u64)
        .try_into()
        .map_err(|_| "slice count overflows u32".to_string())?;
    if file.total_slices != expected {
        return Err(format!(
            "total_slices {} does not match blob_bytes / slice_bytes ceiling {}",
            file.total_slices, expected
        ));
    }
    Ok(())
}

fn validate_id(name: &str, id: &[u8; 32]) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

fn parent_message_context<'a>(
    payload: &'a Fact,
    expected_scope: &FactScope,
    workspace_id: crate::core::facts::FactId,
    message_id: crate::core::facts::FactId,
    label: &str,
) -> Result<ParentMessageContext<'a>, String> {
    if payload.id != message_id {
        return Err("file parent context payload id mismatch".to_string());
    }
    if &payload.scope != expected_scope {
        return Err("file parent context scope does not match file workspace".to_string());
    }
    let parent = decode_parent_message_payload(payload, label)?;
    if parent.workspace_id != workspace_id {
        return Err("file parent message workspace does not match file".to_string());
    }
    Ok(ParentMessageContext {
        _payload: payload,
        message: parent,
    })
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("file author context payload id mismatch".to_string());
    }
    let author_payload = maybe_signed_payload(payload, user::TYPE_USER, "file author")?;
    let author = crate::protocol::auth::user::decode_fact_payload(&author_payload.payload)
        .map_err(|_| "file author context is not an identity user".to_string())?;
    if author.workspace_id != workspace_id {
        return Err("file author workspace does not match file".to_string());
    }
    Ok(())
}

fn validate_file_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_file_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion_payload = maybe_signed_payload(
        payload,
        file_deletion::TYPE_CONTENT_FILE_DELETION,
        "file deletion",
    )?;
    let deletion = file_deletion::decode_fact_payload(&deletion_payload.payload)
        .map_err(|_| "file deletion context is not a content file deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("file deletion workspace does not match file".to_string());
    }
    if deletion.target_file_id != target_file_id {
        return Err("file deletion target does not match file".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("file deletion author does not match file author".to_string());
    }
    Ok(())
}

fn validate_message_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_frontier_id: crate::core::facts::FactId,
    target_minute: u64,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion_payload = maybe_signed_payload(
        payload,
        message_deletion::TYPE_CONTENT_MESSAGE_DELETION,
        "parent deletion",
    )?;
    let deletion = message_deletion::decode_fact_payload(&deletion_payload.payload)
        .map_err(|_| "parent deletion context is not a content message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("parent deletion workspace does not match file".to_string());
    }
    if deletion.target_frontier_id != target_frontier_id {
        return Err("parent deletion frontier does not match file parent".to_string());
    }
    if deletion.target_minute != target_minute {
        return Err("parent deletion minute does not match file parent".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("parent deletion target does not match file parent".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("parent deletion author does not match parent message author".to_string());
    }
    Ok(())
}

struct ParentMessageContext<'a> {
    _payload: &'a Fact,
    message: ParentMessage,
}

struct ParentMessage {
    workspace_id: crate::core::facts::FactId,
    frontier_id: crate::core::facts::FactId,
    minute: u64,
    author_user_id: crate::core::facts::FactId,
}

fn decode_parent_message_payload(payload: &Fact, label: &str) -> Result<ParentMessage, String> {
    let message_payload = maybe_signed_payload(payload, message::TYPE_CONTENT_MESSAGE, label)?;
    let message = message::decode_fact_payload(&message_payload.payload)
        .map_err(|_| format!("{label} context is not a content message"))?;
    Ok(ParentMessage {
        workspace_id: message.workspace_id,
        frontier_id: message.frontier_id,
        minute: message.minute,
        author_user_id: message.author_user_id,
    })
}

fn maybe_signed_payload(
    payload: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if payload.bytes.first().copied() == Some(auth::signed_envelope::TYPE_SIGNED_ENVELOPE) {
        project::decode_raw_or_signed(payload, expected_type, label)
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
        Err("content file fact scope does not match body workspace".to_string())
    }
}

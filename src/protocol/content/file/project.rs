//! Content-file projector.
//!
//! POLICY. A content_file is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped, signed, has valid descriptor
//!      fields, and contains a content_file payload.
//!   2. CONTEXT. Projection waits for signer, parent content message, deletion,
//!      parent deletion, and author context; deletion context removes the
//!      descriptor row and purges this file fact.
//!   3. MATERIALIZE. Live files publish file/exact-fact offers, write the
//!      descriptor row, and share the fact. File bytes remain slice facts.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::Value;
use crate::core::intents::{RowMutation, TableDeleteWhere};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use crate::protocol::content::message::project::{self, FactSigner};
use crate::protocol::content::{
    file_deletion, message, message_deletion, purge::project as content_purge,
};
use crate::protocol::sync::shared_fact::project::{
    context_have_from_optional_needs, retract_fact_from_sync, share_fact_with_sync,
};

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
        project_authenticated::<super::authenticate::ContentFileAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ContentFileAuthenticator>
    for ContentFileProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::ContentFileFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, file) = authenticated.into_parts();
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(file.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context and deletion gates.
        let signer_need = project::signer_need(fact.id, file.workspace_id, file.signer_id);
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
        if !project::validate_signer_context(
            context,
            &signer_need,
            FactSigner {
                signer_id: file.signer_id,
                signer_public_key: file.signer_public_key,
            },
            file.workspace_id,
            Some(file.author_user_id),
            "file",
        )? {
            return Ok(output_with_needs([
                Some(signer_need),
                Some(parent_need),
                Some(author_need),
                None,
            ]));
        }
        let Some(parent_payload) = context_payload(context, &parent_need, "file parent")? else {
            return Ok(output_with_needs([
                Some(signer_need),
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
            return Ok(retract_fact_from_sync(
                delete_file_projection(file.workspace_id, fact.id)
                    .need(parent_need)
                    .need(file_deletion_need)
                    .need(parent_deletion_need)
                    .purge_self(fact.id),
                file.workspace_id,
                fact.id,
                file.created_at_ms,
            ));
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
            return Ok(retract_fact_from_sync(
                delete_file_projection(file.workspace_id, fact.id)
                    .need(file_deletion_need)
                    .need(parent_need)
                    .need(parent_deletion_need)
                    .purge_self(fact.id),
                file.workspace_id,
                fact.id,
                file.created_at_ms,
            ));
        }
        let Some(author) = context_payload(context, &author_need, "file author")? else {
            return Ok(output_with_needs([
                Some(signer_need),
                Some(file_deletion_need),
                Some(parent_need),
                Some(parent_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, file.workspace_id, file.author_user_id)?;
        let context_have = context_have_from_optional_needs(
            context,
            [
                Some(&signer_need),
                Some(&file_deletion_need),
                Some(&parent_need),
                Some(&parent_deletion_need),
                Some(&author_need),
            ],
        );

        // 3. Materialize.
        Ok(share_fact_with_sync(
            output_with_needs([
                Some(signer_need),
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
            .row_mutation(RowMutation::InsertValues(content_file_row(fact.id, &file))),
            file.workspace_id,
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
    let author = crate::protocol::auth::user::decode_fact_payload(payload.body())
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
    let deletion = file_deletion::decode_fact_payload(payload.body())
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
    let deletion = message_deletion::decode_fact_payload(payload.body())
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
    let message = project::decode_typed_fact(
        payload,
        message::TYPE_CONTENT_MESSAGE,
        label,
        message::decode_fact_payload,
    )
    .map_err(|_| format!("{label} context is not a content message"))?;
    Ok(ParentMessage {
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
        Err("content file fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::content::file::fact::{
        ContentFileFact, SealedMetadata, FILE_ROOT_HASH_BYTES,
    };
    use crate::protocol::content::file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES;

    fn valid_file() -> ContentFileFact {
        ContentFileFact {
            workspace_id: [1; 32],
            created_at_ms: 100,
            message_id: [2; 32],
            author_user_id: [3; 32],
            signer_id: [4; 32],
            signer_public_key: [5; 32],
            file_id: [6; 32],
            blob_bytes: 1,
            total_slices: 1,
            slice_bytes: FILE_SLICE_PLAINTEXT_BYTES as u32,
            root_hash: [7; FILE_ROOT_HASH_BYTES],
            sealed_metadata: SealedMetadata::new(b"sealed").expect("metadata"),
            signature: [8; crate::core::crypto::ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn non_empty_files_use_the_fixed_slice_budget() {
        let mut file = valid_file();
        file.slice_bytes = 1_024;

        let err = super::super::authenticate::validate_file_fields(&file)
            .expect_err("reject non-standard slice budget");

        assert!(
            err.contains("fixed file-slice slot"),
            "unexpected error: {err}"
        );
    }
}

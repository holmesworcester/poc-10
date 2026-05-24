//! Poc-10 content-file-slice projector.
//!
//! POLICY. A content_file_slice is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and its parent file selector
//!      and slice index decode from the canonical payload.
//!   2. CONTEXT. Projection waits for the parent file, rejects out-of-range
//!      indexes, and watches parent file/message deletion context.
//!   3. MATERIALIZE. Live slices write one row and share the fact; deleted
//!      parents delete the slice row and purge this slice fact. AEAD opening
//!      stays in auth key-material code.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::Value;
use crate::core::intents::{RowMutation, TableDeleteWhere};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::content::file;
use crate::protocol::content::file_deletion;
use crate::protocol::content::message;
use crate::protocol::content::message::fact::unix_minute_for;
use crate::protocol::content::message::project as message_project;
use crate::protocol::content::message_deletion;
use crate::protocol::content::purge::project as content_purge;
use crate::protocol::sync::shared_fact::project::{
    context_have_from_needs, share_fact_with_negentropy,
};

use super::rows::{content_file_slice_row, FILE_SLICE_KEY_COLUMNS, FILE_SLICE_ROWS};

#[derive(Debug, Clone, Default)]
pub struct ContentFileSliceProjector;

impl ContentFileSliceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileSliceProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentFileSliceProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        slice: super::fact::ContentFileSliceFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(slice.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context and deletion gates.
        let file_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_file",
            scope.clone(),
            slice.file_id,
            slice.file_id,
        );
        let Some(parent) = context_payload(context, &file_need, "file slice parent")? else {
            return Ok(ProjectionOutput::new().need(file_need));
        };
        let file = message_project::decode_signed_payload(
            parent,
            file::TYPE_CONTENT_FILE,
            "file slice parent",
        )?
        .payload;
        let file = file::decode_fact_payload(&file)
            .map_err(|_| "file slice parent context is not a content file".to_string())?;
        if parent.scope != scope {
            return Err("file slice parent scope does not match slice".to_string());
        }
        if file.workspace_id != slice.workspace_id {
            return Err("file slice parent workspace does not match slice".to_string());
        }
        if file.file_id != slice.file_id {
            return Err("file slice parent file_id does not match slice".to_string());
        }
        if slice.slice_index >= file.total_slices {
            return Err("file slice index is out of range for parent file".to_string());
        }
        let message_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message",
            scope.clone(),
            file.message_id,
            file.message_id,
        );
        let Some(message_payload) =
            context_payload(context, &message_need, "file slice message parent")?
        else {
            return Ok(ProjectionOutput::new().need(file_need).need(message_need));
        };
        let parent_message = message_project::decode_signed_fact(
            message_payload,
            message::TYPE_CONTENT_MESSAGE,
            "file slice message parent",
            message::decode_fact_payload,
        )?
        .payload;
        if parent_message.workspace_id != slice.workspace_id {
            return Err("file slice message parent workspace does not match slice".to_string());
        }
        let file_deletion_need = content_purge::target_purged_need(
            fact.id,
            scope.clone(),
            parent_message.frontier_id,
            unix_minute_for(file.created_at_ms),
            parent.id,
        );
        let parent_deletion_need = content_purge::target_purged_need(
            fact.id,
            scope,
            parent_message.frontier_id,
            parent_message.minute,
            file.message_id,
        );
        if let Some(deletion) = context_payload(
            context,
            &parent_deletion_need,
            "file slice message parent deletion",
        )? {
            validate_message_deletion(
                deletion,
                file.workspace_id,
                parent_message.frontier_id,
                parent_message.minute,
                file.message_id,
                parent_message.author_user_id,
            )?;
            return Ok(ProjectionOutput::new()
                .need(file_need)
                .need(message_need)
                .need(file_deletion_need)
                .need(parent_deletion_need)
                .row_mutation(RowMutation::DeleteWhere(content_file_slice_delete(
                    slice.workspace_id,
                    slice.file_id,
                    slice.slice_index,
                )))
                .purge_self(fact.id));
        }
        if let Some(deletion) =
            context_payload(context, &file_deletion_need, "file slice parent deletion")?
        {
            validate_file_deletion(deletion, file.workspace_id, parent.id, file.author_user_id)?;
            return Ok(ProjectionOutput::new()
                .need(file_need)
                .need(message_need)
                .need(file_deletion_need)
                .need(parent_deletion_need)
                .row_mutation(RowMutation::DeleteWhere(content_file_slice_delete(
                    slice.workspace_id,
                    slice.file_id,
                    slice.slice_index,
                )))
                .purge_self(fact.id));
        }
        let context_have = context_have_from_needs(
            context,
            [
                &file_need,
                &message_need,
                &file_deletion_need,
                &parent_deletion_need,
            ],
        );

        // 3. Materialize.
        Ok(share_fact_with_negentropy(
            ProjectionOutput::new()
                .need(file_need)
                .need(message_need)
                .need(file_deletion_need)
                .need(parent_deletion_need)
                .row_mutation(RowMutation::InsertValues(content_file_slice_row(
                    fact.id, &slice,
                ))),
            slice.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    context.payload_for_checked(need, label)
}

fn validate_file_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_file_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion_payload = message_project::decode_signed_payload(
        payload,
        file_deletion::TYPE_CONTENT_FILE_DELETION,
        "file slice parent deletion",
    )?;
    let deletion = file_deletion::decode_fact_payload(&deletion_payload.payload).map_err(|_| {
        "file slice parent deletion context is not a content file deletion".to_string()
    })?;
    if deletion.workspace_id != workspace_id {
        return Err("file slice parent deletion workspace does not match slice".to_string());
    }
    if deletion.target_file_id != target_file_id {
        return Err("file slice parent deletion target does not match parent file".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err(
            "file slice parent deletion author does not match parent file author".to_string(),
        );
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
    let deletion = message_project::decode_signed_fact(
        payload,
        message_deletion::TYPE_CONTENT_MESSAGE_DELETION,
        "file slice message parent deletion",
        message_deletion::decode_fact_payload,
    )?
    .payload;
    if deletion.workspace_id != workspace_id {
        return Err("file slice message deletion workspace does not match slice".to_string());
    }
    if deletion.target_frontier_id != target_frontier_id {
        return Err("file slice message deletion frontier does not match parent".to_string());
    }
    if deletion.target_minute != target_minute {
        return Err("file slice message deletion minute does not match parent".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("file slice message deletion target does not match parent".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("file slice message deletion author does not match parent".to_string());
    }
    Ok(())
}

fn content_file_slice_delete(
    workspace_id: FactId,
    file_id: FactId,
    slice_index: u32,
) -> TableDeleteWhere {
    TableDeleteWhere {
        table: FILE_SLICE_ROWS,
        columns: FILE_SLICE_KEY_COLUMNS,
        values: vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::Bytes(file_id.to_vec()),
            Value::U64(u64::from(slice_index)),
        ],
    }
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file slice fact scope does not match body workspace".to_string())
    }
}

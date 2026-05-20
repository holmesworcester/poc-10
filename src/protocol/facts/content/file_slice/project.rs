//! Poc-10 content-file-slice projector.
//!
//! POLICY. A content_file_slice is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and its parent file selector
//!      and slice index decode from the canonical payload.
//!   2. CONTEXT. Projection waits for the parent file, rejects out-of-range
//!      indexes, and watches parent deletion context.
//!   3. MATERIALIZE. Live slices write one row and share the fact; deleted
//!      parents delete the slice row. AEAD opening stays in encryption code.

use crate::core::context::ContextNeed;
use crate::core::facts::Fact;
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::facts::content::file;
use crate::protocol::facts::content::file_deletion;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers as file_matchers;
use crate::protocol::matchers as message_matchers;

use super::rows::{content_file_slice_key, content_file_slice_row, FILE_SLICE_ROWS};

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
        let scope = message_matchers::workspace_scope(slice.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context and deletion gates.
        let file_need = file_matchers::file_need(fact.id, scope.clone(), slice.file_id);
        let Some(parent) = context_payload(context, &file_need, "file slice parent")? else {
            return Ok(ProjectionOutput::new().need(file_need));
        };
        let file = file::decode_fact_payload(&parent.bytes)
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
        let file_deletion_need =
            message_matchers::deletion_need(fact.id, scope, parent.id, file.author_user_id);
        if let Some(deletion) =
            context_payload(context, &file_deletion_need, "file slice parent deletion")?
        {
            validate_file_deletion(deletion, file.workspace_id, parent.id, file.author_user_id)?;
            return Ok(ProjectionOutput::new()
                .need(file_need)
                .need(file_deletion_need)
                .intent(
                    AtomicIntent::DeleteRow(TableDelete {
                        table: FILE_SLICE_ROWS,
                        key: content_file_slice_key(
                            &slice.workspace_id,
                            &slice.file_id,
                            slice.slice_index,
                        ),
                    })
                    .into_intent(),
                ));
        }

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(file_need)
            .need(file_deletion_need)
            .intent(AtomicIntent::PutRow(content_file_slice_row(fact.id, &slice)?).into_intent())
            .intent(share_fact_with_workspace_intent_for_fact(
                slice.workspace_id,
                fact,
            )))
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
    let deletion = file_deletion::decode_fact_payload(payload.body()).map_err(|_| {
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

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file slice fact scope does not match body workspace".to_string())
    }
}

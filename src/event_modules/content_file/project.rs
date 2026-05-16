//! Poc-10 content-file projector.
//!
//! Decodes a content-file fact and emits a single `PutRow` into `file_rows`.
//! The file event id used in the row key is the fact id.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Signed-envelope verification (separate event module).
//! - Author workspace-membership cross-check (depends on identity-membership
//!   projections that haven't landed in the target tree yet).
//! - Sibling message dependency / tombstone cascade depends on per-message
//!   tombstone rows and is handled outside this row projector.
//! - `blob_bytes <= MAX_FILE_BYTES` and `total_slices * slice_bytes >=
//!   blob_bytes` invariants — legacy ran these against pre-decryption sizes.
//!   The target slice-budget enforcement will move into the file-send command
//!   wave; this projector only owns the row layout.
//! - Per-file leaf-coord / frontier derivation — depends on per-message FS.
//! - Sealed-metadata AEAD opening — depends on encryption module surfacing the
//!   per-file content key.

use crate::core::facts::Fact;
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_message::{
    layout as message_layout, matchers as message_matchers,
};

use super::layout;
use super::matchers;
use super::rows::{content_file_key, content_file_row, FILE_ROWS};

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
        let file = layout::decode_fact(&fact.bytes)?;
        let scope = message_matchers::workspace_scope(file.workspace_id);
        require_fact_scope(fact, &scope)?;
        let file_deletion_need =
            message_matchers::deletion_need(fact.id, scope.clone(), fact.id, file.author_user_id);
        if let Some(deletion) = context.payload_for(&file_deletion_need) {
            validate_file_deletion(deletion, file.workspace_id, fact.id, file.author_user_id)?;
            return Ok(delete_file_projection(file.workspace_id, fact.id));
        }
        let parent_need = message_matchers::message_need(fact.id, scope.clone(), file.message_id);
        let Some(parent) = context.payload_for(&parent_need) else {
            return Ok(ProjectionOutput::new()
                .need(parent_need)
                .need(file_deletion_need));
        };
        let parent_message = message_layout::decode_fact(&parent.bytes)
            .map_err(|_| "file parent context is not a content message".to_string())?;
        if parent_message.workspace_id != file.workspace_id {
            return Err("file parent message workspace does not match file".to_string());
        }
        let parent_deletion_need = message_matchers::deletion_need(
            fact.id,
            scope.clone(),
            file.message_id,
            parent_message.author_user_id,
        );
        if let Some(deletion) = context.payload_for(&parent_deletion_need) {
            validate_message_deletion(
                deletion,
                file.workspace_id,
                file.message_id,
                parent_message.author_user_id,
            )?;
            return Ok(delete_file_projection(file.workspace_id, fact.id));
        }
        Ok(ProjectionOutput::new()
            .need(file_deletion_need)
            .need(parent_deletion_need)
            .offer(matchers::file_offer(fact.id, scope, file.file_id))
            .intent(AtomicIntent::PutRow(content_file_row(fact.id, &file)?).into_intent()))
    }
}

fn delete_file_projection(
    workspace_id: crate::core::facts::FactId,
    file_event_id: crate::core::facts::FactId,
) -> ProjectionOutput {
    ProjectionOutput::new().intent(
        AtomicIntent::DeleteRow(TableDelete {
            table: FILE_ROWS,
            key: content_file_key(&workspace_id, &file_event_id),
        })
        .into_intent(),
    )
}

fn validate_file_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_file_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion = crate::event_modules::content_file_deletion::layout::decode_fact(&payload.bytes)
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
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion =
        crate::event_modules::content_message_deletion::layout::decode_fact(&payload.bytes)
            .map_err(|_| "parent deletion context is not a content message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("parent deletion workspace does not match file".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("parent deletion target does not match file parent".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("parent deletion author does not match parent message author".to_string());
    }
    Ok(())
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file fact scope does not match body workspace".to_string())
    }
}

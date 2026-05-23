//! User-facing content-file deletion commands.
//!
//! Commands stamp deterministic constructors with command context and return
//! receipts only. Projection and purge effects happen after runtime drain.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::facts::FactId;

use super::create;
use super::fact::{AuthorId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteFileReceipt {
    pub workspace_id: WorkspaceId,
    pub deletion_fact_id: FactId,
    pub target_file_id: FactId,
    pub author_user_id: AuthorId,
    pub created_at_ms: u64,
}

pub fn delete_file(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
    target_file_id: FactId,
    author_user_id: AuthorId,
) -> Result<CommandOutput<DeleteFileReceipt>, String> {
    let created_at_ms = ctx.next_timestamp();
    create::validate_delete_file(workspace_id, target_file_id, author_user_id)?;
    let signing = ctx.local_signing_capability(workspace_id)?;
    let fact = create::delete_file(
        &signing,
        workspace_id,
        created_at_ms,
        target_file_id,
        author_user_id,
    )?;
    Ok(CommandOutput::new(DeleteFileReceipt {
        workspace_id,
        deletion_fact_id: fact.id,
        target_file_id,
        author_user_id,
        created_at_ms,
    })
    .with_facts(vec![fact]))
}

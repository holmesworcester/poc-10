//! User-facing content-message deletion commands.
//!
//! Commands stamp deterministic constructors with command context and return
//! receipts only. Projection and purge effects happen after runtime drain.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::facts::FactId;

use super::create;
use super::fact::{AuthorId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteMessageReceipt {
    pub workspace_id: WorkspaceId,
    pub deletion_fact_id: FactId,
    pub target_message_id: FactId,
    pub target_frontier_id: FactId,
    pub target_minute: u64,
    pub author_user_id: AuthorId,
    pub created_at_ms: u64,
}

pub fn delete_message(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
    target_message_id: FactId,
    target_frontier_id: FactId,
    target_minute: u64,
    author_user_id: AuthorId,
) -> Result<CommandOutput<DeleteMessageReceipt>, String> {
    let created_at_ms = ctx.next_timestamp();
    let fact = create::delete_message(
        workspace_id,
        created_at_ms,
        target_message_id,
        target_frontier_id,
        target_minute,
        author_user_id,
    )?;
    Ok(CommandOutput::new(DeleteMessageReceipt {
        workspace_id,
        deletion_fact_id: fact.id,
        target_message_id,
        target_frontier_id,
        target_minute,
        author_user_id,
        created_at_ms,
    })
    .with_facts(vec![fact]))
}

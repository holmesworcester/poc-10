//! Command-facing workspace workflows.
//!
//! Commands receive stable context and compose deterministic constructors. They
//! do not project, write rows, or call intent handlers.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::event_modules::identity_workspace::create;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceReceipt {
    pub workspace_fact_id: FactId,
    pub created_at_ms: u64,
}

pub fn create_workspace(
    ctx: &CommandContext<'_>,
    public_key: Ed25519PublicKey,
    name: &str,
) -> Result<CommandOutput<CreateWorkspaceReceipt>, String> {
    let created_at_ms = ctx.next_timestamp();
    let fact = create::create_workspace(created_at_ms, public_key, name)?;
    let receipt = CreateWorkspaceReceipt {
        workspace_fact_id: fact.id,
        created_at_ms,
    };
    Ok(CommandOutput::new(receipt).with_facts(vec![fact]))
}

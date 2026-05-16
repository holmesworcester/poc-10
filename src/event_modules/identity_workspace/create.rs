//! `create_workspace`: construct a workspace root fact through `CommandContext`.
//!
//! The command takes the caller-chosen workspace public key (which identity
//! authored separately) and stamps it with the current monotonic timestamp.
//! It does not mint signing material, does not query the store, and does not
//! run a worker. The returned `WorkspaceFact` is ready for ordinary admission
//! through the target `WakeLoop`.

use crate::commands::context::{CommandContext, CommandOutput};
use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::{Fact, FactScope};
use crate::event_modules::identity_workspace::fact::{WorkspaceFact, WORKSPACE_NAME_BYTES};
use crate::event_modules::identity_workspace::layout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceSummary {
    pub workspace_fact_id: crate::core::facts::FactId,
    pub created_at_ms: u64,
    pub name: String,
}

pub fn create_workspace(
    ctx: &CommandContext<'_>,
    public_key: Ed25519PublicKey,
    name: &str,
) -> Result<CommandOutput<CreateWorkspaceSummary>, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("create_workspace name must not be blank".to_string());
    }
    if name.as_bytes().len() > WORKSPACE_NAME_BYTES {
        return Err(format!(
            "create_workspace name exceeds {WORKSPACE_NAME_BYTES} byte slot"
        ));
    }

    let created_at_ms = ctx.next_timestamp();
    let workspace = WorkspaceFact {
        created_at_ms,
        public_key,
        name: name.to_string(),
    };
    let bytes = layout::encode_fact(&workspace)?;
    let fact = Fact::new(FactScope::Global, created_at_ms, bytes);
    let summary = CreateWorkspaceSummary {
        workspace_fact_id: fact.id,
        created_at_ms,
        name: name.to_string(),
    };
    Ok(CommandOutput::new(summary).with_facts(vec![fact]))
}

//! Deterministic constructors for content-message deletion facts.
//!
//! This layer takes already-resolved parameters and returns canonical fact
//! bytes. User-facing timestamping and receipts live in `commands.rs`.

use crate::core::facts::{Fact, FactId};
use crate::protocol::matchers;

use super::fact::{AuthorId, ContentMessageDeletionFact, WorkspaceId};
use super::layout;

pub fn delete_message(
    workspace_id: WorkspaceId,
    created_at_ms: u64,
    target_message_id: FactId,
    author_user_id: AuthorId,
) -> Result<Fact, String> {
    require_nonzero_id("delete_message workspace_id", &workspace_id)?;
    require_nonzero_id("delete_message target_message_id", &target_message_id)?;
    require_nonzero_id("delete_message author_user_id", &author_user_id)?;

    let deletion = ContentMessageDeletionFact {
        workspace_id,
        created_at_ms,
        target_message_id,
        author_user_id,
    };
    Ok(Fact::new(
        matchers::workspace_scope(workspace_id),
        created_at_ms,
        layout::encode_fact(&deletion)?,
    ))
}

fn require_nonzero_id(name: &str, id: &FactId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

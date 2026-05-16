//! Deterministic constructors for content-file deletion facts.
//!
//! This layer takes already-resolved parameters and returns canonical fact
//! bytes. User-facing timestamping and receipts live in `commands.rs`.

use crate::core::facts::{Fact, FactId};
use crate::protocol::matchers;

use super::fact::{AuthorId, ContentFileDeletionFact, WorkspaceId};
use super::layout;

pub fn delete_file(
    workspace_id: WorkspaceId,
    created_at_ms: u64,
    target_file_id: FactId,
    author_user_id: AuthorId,
) -> Result<Fact, String> {
    require_nonzero_id("delete_file workspace_id", &workspace_id)?;
    require_nonzero_id("delete_file target_file_id", &target_file_id)?;
    require_nonzero_id("delete_file author_user_id", &author_user_id)?;

    let deletion = ContentFileDeletionFact {
        workspace_id,
        created_at_ms,
        target_file_id,
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

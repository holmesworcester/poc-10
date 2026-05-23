//! Deterministic constructors for content-file deletion facts.
//!
//! This layer takes already-resolved parameters and returns canonical fact
//! bytes. User-facing timestamping and receipts live in `commands.rs`.

use crate::core::command_context::LocalSigningCapability;
use crate::core::facts::{Fact, FactId};
use crate::protocol::auth::signed_fact;

use super::fact::{AuthorId, ContentFileDeletionFact, WorkspaceId};
use super::layout;

pub fn delete_file(
    signing: &LocalSigningCapability,
    workspace_id: WorkspaceId,
    created_at_ms: u64,
    target_file_id: FactId,
    author_user_id: AuthorId,
) -> Result<Fact, String> {
    validate_delete_file(workspace_id, target_file_id, author_user_id)?;
    if signing.workspace_id != workspace_id {
        return Err("delete_file signing capability workspace mismatch".to_string());
    }

    let deletion = ContentFileDeletionFact {
        workspace_id,
        created_at_ms,
        target_file_id,
        author_user_id,
    };
    let payload = layout::encode_fact(&deletion)?;
    let bytes =
        signed_fact::create::sign_payload_bytes(signing.signer_id, &signing.private_key, payload)?;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        bytes,
    ))
}

pub(crate) fn validate_delete_file(
    workspace_id: WorkspaceId,
    target_file_id: FactId,
    author_user_id: AuthorId,
) -> Result<(), String> {
    require_nonzero_id("delete_file workspace_id", &workspace_id)?;
    require_nonzero_id("delete_file target_file_id", &target_file_id)?;
    require_nonzero_id("delete_file author_user_id", &author_user_id)?;
    Ok(())
}

fn require_nonzero_id(name: &str, id: &FactId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

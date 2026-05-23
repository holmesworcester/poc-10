//! Deterministic constructors for content-message deletion facts.
//!
//! This layer takes already-resolved parameters and returns canonical fact
//! bytes. User-facing timestamping and receipts live in `commands.rs`.

use crate::core::command_context::LocalSigningCapability;
use crate::core::facts::{Fact, FactId};
use crate::protocol::auth::signed_fact;

use super::fact::{AuthorId, ContentMessageDeletionFact, WorkspaceId};
use super::layout;

pub fn delete_message(
    signing: &LocalSigningCapability,
    workspace_id: WorkspaceId,
    created_at_ms: u64,
    target_message_id: FactId,
    target_frontier_id: FactId,
    target_minute: u64,
    author_user_id: AuthorId,
) -> Result<Fact, String> {
    validate_delete_message(
        workspace_id,
        target_message_id,
        target_frontier_id,
        author_user_id,
    )?;
    if signing.workspace_id != workspace_id {
        return Err("delete_message signing capability workspace mismatch".to_string());
    }

    let deletion = ContentMessageDeletionFact {
        workspace_id,
        created_at_ms,
        target_message_id,
        target_frontier_id,
        target_minute,
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

pub(crate) fn validate_delete_message(
    workspace_id: WorkspaceId,
    target_message_id: FactId,
    target_frontier_id: FactId,
    author_user_id: AuthorId,
) -> Result<(), String> {
    require_nonzero_id("delete_message workspace_id", &workspace_id)?;
    require_nonzero_id("delete_message target_message_id", &target_message_id)?;
    require_nonzero_id("delete_message target_frontier_id", &target_frontier_id)?;
    require_nonzero_id("delete_message author_user_id", &author_user_id)?;
    Ok(())
}

fn require_nonzero_id(name: &str, id: &FactId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

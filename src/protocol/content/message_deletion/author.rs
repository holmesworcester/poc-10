//! Deterministic constructors for content-message deletion facts.
//!
//! This layer takes already-resolved parameters and returns canonical fact
//! bytes. User-facing timestamping and receipts live in `commands.rs`.

use crate::core::command::LocalSigningCapability;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};

use super::encode;
use super::fact::{AuthorId, ContentMessageDeletionFact, WorkspaceId};

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

    let signer_public_key = crypto::ed25519_public_key(&signing.private_key);
    let deletion = ContentMessageDeletionFact {
        workspace_id,
        created_at_ms,
        target_message_id,
        target_frontier_id,
        target_minute,
        author_user_id,
        signer_id: signing.signer_id,
        signer_public_key,
    };
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        encode::encode_fact(&deletion)?,
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

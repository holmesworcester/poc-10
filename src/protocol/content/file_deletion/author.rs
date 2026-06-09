//! Deterministic constructors for content-file deletion facts.
//!
//! This layer takes already-resolved parameters and returns canonical fact
//! bytes. User-facing timestamping and receipts live in `commands.rs`.

use crate::core::command_context::LocalSigningCapability;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::protocol::root;

use super::encode;
use super::fact::{AuthorId, ContentFileDeletionFact, WorkspaceId};

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

    let signer_public_key = crypto::ed25519_public_key(&signing.private_key);
    let deletion = ContentFileDeletionFact {
        workspace_id,
        created_at_ms,
        target_file_id,
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

pub fn delete_file_root(
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

    let root = root::fact::RootFact {
        family: super::ROOT_FAMILY_CONTENT_FILE_DELETION,
        version: super::ROOT_VERSION_CONTENT_FILE_DELETION,
        created_at_ms,
        refs: vec![
            root::fact::RootRef::new(root::roles::WORKSPACE, 0, workspace_id)?,
            root::fact::RootRef::new(root::roles::AUTHOR, 0, author_user_id)?,
            root::fact::RootRef::new(root::roles::SIGNER, 0, signing.signer_id)?,
            root::fact::RootRef::new(root::roles::TARGET, 0, target_file_id)?,
        ],
    };
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        root::encode::encode_fact(&root)?,
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

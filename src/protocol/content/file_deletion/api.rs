//! User-facing content-file deletion commands.
//!
//! Commands query local authority from the store, stamp deterministic
//! constructors with the command clock, and return receipts only. Projection
//! and purge effects happen after runtime drain.

use crate::core::command::{AuthoredFacts, CommandClock};
use crate::core::db::Db;
use crate::core::facts::FactId;
use crate::protocol::auth;

use super::author;
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
    store: &Db,
    clock: &dyn CommandClock,
    workspace_id: WorkspaceId,
    target_file_id: FactId,
    author_user_id: AuthorId,
) -> Result<AuthoredFacts<DeleteFileReceipt>, String> {
    let created_at_ms = clock.next_timestamp();
    author::validate_delete_file(workspace_id, target_file_id, author_user_id)?;
    let signing = auth::endpoint::api::local_signing_capability(store, workspace_id)?;
    let fact = author::delete_file(
        &signing,
        workspace_id,
        created_at_ms,
        target_file_id,
        author_user_id,
    )?;
    let signature = auth::signature::author::sign_fact(
        workspace_id,
        &fact,
        &signing.private_key,
        created_at_ms,
    )?;
    Ok(AuthoredFacts::new(DeleteFileReceipt {
        workspace_id,
        deletion_fact_id: fact.id,
        target_file_id,
        author_user_id,
        created_at_ms,
    })
    .with_facts(vec![fact, signature]))
}

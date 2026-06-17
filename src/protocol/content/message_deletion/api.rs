//! User-facing content-message deletion commands.
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
    store: &Db,
    clock: &dyn CommandClock,
    workspace_id: WorkspaceId,
    target_message_id: FactId,
    target_frontier_id: FactId,
    target_minute: u64,
    author_user_id: AuthorId,
) -> Result<AuthoredFacts<DeleteMessageReceipt>, String> {
    let created_at_ms = clock.next_timestamp();
    author::validate_delete_message(
        workspace_id,
        target_message_id,
        target_frontier_id,
        author_user_id,
    )?;
    let signing = auth::endpoint::api::local_signing_capability(store, workspace_id)?;
    let fact = author::delete_message(
        &signing,
        workspace_id,
        created_at_ms,
        target_message_id,
        target_frontier_id,
        target_minute,
        author_user_id,
    )?;
    let signature = auth::signature::author::sign_fact(
        workspace_id,
        &fact,
        &signing.private_key,
        created_at_ms,
    )?;
    Ok(AuthoredFacts::new(DeleteMessageReceipt {
        workspace_id,
        deletion_fact_id: fact.id,
        target_message_id,
        target_frontier_id,
        target_minute,
        author_user_id,
        created_at_ms,
    })
    .with_facts(vec![fact, signature]))
}

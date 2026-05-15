//! Poc-10 content-message-deletion projector.
//!
//! Decodes a deletion fact and emits a single `PutRow` into
//! `message_deletion_rows`, keyed by `(workspace_id, target_message_id)`.
//! The fact's own id is preserved in the row value so cascade handlers can
//! correlate the deletion back to its originating fact.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Legacy validates a signed envelope around the payload that binds an
//!   endpoint_shared signer to the named author. The target signed-fact
//!   envelope and identity dependency context (endpoint_shared, user) are
//!   separate event modules and not consulted here.
//! - Legacy enqueues a `purge_instructions` row into the content-purge queue
//!   so the worker can cascade physical cleanup. The target purge queue lives
//!   in a separate handler module and is deferred to that slice.
//! - Legacy emits a context update labelling the target message id with the
//!   deletion author. The target context-update channel is not yet wired into
//!   the projection pipeline and is deferred.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::{message_deletion_row, MessageDeletionRow};

#[derive(Debug, Clone, Default)]
pub struct ContentMessageDeletionProjector;

impl ContentMessageDeletionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentMessageDeletionProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let deletion = layout::decode_fact(&fact.bytes)?;
        let row = message_deletion_row(MessageDeletionRow {
            workspace_id: deletion.workspace_id,
            target_message_id: deletion.target_message_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        })?;
        Ok(ProjectionOutput::new().intent(AtomicIntent::PutRow(row).into_intent()))
    }
}

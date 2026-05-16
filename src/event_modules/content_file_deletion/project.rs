//! Poc-10 content-file-deletion projector.
//!
//! Decodes a deletion fact and emits a single `PutRow` into `file_deletion_rows`,
//! keyed by `(workspace_id, target_file_id)`. The fact's own id is preserved in
//! the row value so cascade handlers can correlate the deletion back to its
//! originating fact.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Legacy validates a signed envelope around the payload that binds an
//!   endpoint_shared signer to the named author. The target signed-fact
//!   envelope and identity dependency context are separate event modules and
//!   not consulted here.
//! - Physical cleanup orchestration is handled outside this row projector.
//! - Legacy emits a context update labelling the target file id with the
//!   deletion author. The target context-update channel is not yet wired into
//!   the projection pipeline and is deferred.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_message::matchers;

use super::layout;
use super::rows::{file_deletion_row, FileDeletionRow};

#[derive(Debug, Clone, Default)]
pub struct ContentFileDeletionProjector;

impl ContentFileDeletionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentFileDeletionProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let deletion = layout::decode_fact(&fact.bytes)?;
        let scope = matchers::workspace_scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;
        let row = file_deletion_row(FileDeletionRow {
            workspace_id: deletion.workspace_id,
            target_file_id: deletion.target_file_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        })?;
        Ok(ProjectionOutput::new()
            .offer(matchers::deletion_offer(
                fact.id,
                scope,
                deletion.target_file_id,
                deletion.author_user_id,
            ))
            .intent(AtomicIntent::PutRow(row).into_intent()))
    }
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content file deletion fact scope does not match body workspace".to_string())
    }
}

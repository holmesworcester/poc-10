//! Poc-10 content-reaction projector.
//!
//! Decodes a content-reaction fact and emits a single `PutRow` into
//! `reaction_rows`. The reaction id used in the row key is the fact id.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Legacy validates a signed envelope around the payload; the target
//!   signed-fact envelope is a separate event module.
//! - Legacy admit-check drops reactions whose parent message is already
//!   tombstoned. That cascade lives in the content-purge handler in poc-10
//!   and depends on the message tombstone projection.
//! - Legacy derives a deterministic leaf coordinate from author+target+
//!   frontier+ts so duplicate reactions collapse on admission. The target
//!   per-message FS isn't ported yet, so this slice keys rows by fact id.
//! - Legacy decrypts the emoji into a plaintext `content.reactions` row;
//!   per-message decryption secrets aren't surfaced in this slice.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::{reaction_row, ReactionRow};

#[derive(Debug, Clone, Default)]
pub struct ContentReactionProjector;

impl ContentReactionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentReactionProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let reaction = layout::decode_fact(&fact.bytes)?;
        let row = reaction_row(ReactionRow {
            workspace_id: reaction.workspace_id,
            reaction_id: fact.id,
            created_at_ms: reaction.created_at_ms,
            target_message_id: reaction.target_message_id,
            author_user_id: reaction.author_user_id,
            nonce: reaction.nonce,
            ciphertext: reaction.ciphertext,
        })?;
        Ok(ProjectionOutput::new().intent(AtomicIntent::PutRow(row).into_intent()))
    }
}

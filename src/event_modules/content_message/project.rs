//! Poc-10 content-message projector.
//!
//! Decodes a content-message fact and emits a single `PutRow` into
//! `content_message_rows`. The message id used in the row key is the fact id.
//!
//! Parity gaps (intentional, deferred to later slices):
//!  - Legacy validates a signed envelope, a workspace-membership chain for the
//!    signer endpoint, and an author dependency on a signed user event. The
//!    target signed-fact and identity modules are wired in separate slices.
//!  - Legacy binds the message to a per-message leaf event dependency and
//!    recomputes the deterministic leaf coordinate from canonical fields.
//!    The target leaf module isn't surfaced here; the projector trusts the
//!    `leaf_id`/`minute` hints inside the fact.
//!  - Legacy resolves the referenced disappearing-messages setting and
//!    rejects `expires_at_minute` mismatches; the setting module is not
//!    ported.
//!  - Legacy purges on a self-deletion label and writes tombstone rows; the
//!    deletion projector is a separate event module.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::content_message_row;

#[derive(Debug, Clone, Default)]
pub struct ContentMessageProjector;

impl ContentMessageProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentMessageProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let message = layout::decode_fact(&fact.bytes)?;
        let row = content_message_row(fact.id, &message);
        Ok(ProjectionOutput::new().intent(AtomicIntent::PutRow(row).into_intent()))
    }
}

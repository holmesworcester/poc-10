//! Poc-10 content-event projector.
//!
//! Validates the fact's declared payload length against its bytes (the layout
//! decoder already checks this) and emits a single `PutRow` for the
//! content_event_rows table.
//!
//! Legacy parity gap (intentional): the legacy projector also validated a
//! signed envelope and a workspace-membership dependency for the signer. The
//! target signed-fact envelope and identity membership are separate event
//! modules; the content-event projector here only owns the row layout.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::content_event_row;

#[derive(Debug, Clone, Default)]
pub struct ContentEventProjector;

impl ContentEventProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentEventProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let event = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(content_event_row(fact.id, &event)?).into_intent()))
    }
}

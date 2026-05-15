//! Poc-10 sync have-id projector.
//!
//! Decodes the have-id fact and emits a single `PutRow` for
//! `sync_have_id_rows`. The legacy projector also queued transit work for
//! the cached event; that responsibility now lives in transit handlers.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::sync_have_id_row;

#[derive(Debug, Clone, Default)]
pub struct SyncHaveIdProjector;

impl SyncHaveIdProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncHaveIdProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let have = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(sync_have_id_row(fact.id, &have)?).into_intent()))
    }
}

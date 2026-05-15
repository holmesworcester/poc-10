//! Poc-10 sync need-id projector.
//!
//! Decodes the need-id fact and emits a single `PutRow` for
//! `sync_need_id_rows`. The legacy projector also queued transit work and
//! prepared the response path; both responsibilities now live in transit
//! handlers.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::sync_need_id_row;

#[derive(Debug, Clone, Default)]
pub struct SyncNeedIdProjector;

impl SyncNeedIdProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncNeedIdProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let need = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(sync_need_id_row(fact.id, &need)?).into_intent()))
    }
}

//! Poc-10 sync compare projector.
//!
//! Decodes the compare fact and emits a single `PutRow` for
//! `sync_compare_rows`. The legacy projector also routed the event onto a
//! connection's transit queues; that is now a transit handler concern and
//! lives outside this module.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::sync_compare_row;

#[derive(Debug, Clone, Default)]
pub struct SyncCompareProjector;

impl SyncCompareProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncCompareProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let compare = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(sync_compare_row(fact.id, &compare)?).into_intent()))
    }
}

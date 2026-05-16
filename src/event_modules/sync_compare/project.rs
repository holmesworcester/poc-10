//! Poc-10 sync compare projector.
//!
//! Decodes the compare fact, materializes `sync_compare_rows`, and emits the
//! bounded deferred response intent when the peer explicitly requests an
//! answer. Transit can only carry a response after sync has produced one.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::handlers::handle_sync::{respond_to_sync_compare_intent, RespondToSyncCompare};

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
        let mut output = ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(sync_compare_row(fact.id, &compare)?).into_intent());
        if compare.response_requested {
            output = output.intent(respond_to_sync_compare_intent(RespondToSyncCompare {
                compare_fact_id: fact.id,
            }));
        }
        Ok(output)
    }
}

//! Poc-10 sync compare projector.
//!
//! POLICY. A sync_compare fact is admitted iff:
//!   1. STRUCTURAL. The compare payload decodes with its range summary.
//!   2. CONTEXT. No matched context is required; this is a peer summary.
//!   3. MATERIALIZE. Write the compare row and emit deferred response work only
//!      when the peer explicitly requested an answer.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::intents::sync::send_compare_response::{
    send_sync_compare_response_intent, SendSyncCompareResponse,
};

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
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for SyncCompareProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        compare: super::fact::SyncCompareFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        // 3. Materialize.
        let mut output = ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(sync_compare_row(fact.id, &compare)?).into_intent());
        if compare.response_requested {
            output = output.intent(send_sync_compare_response_intent(SendSyncCompareResponse {
                compare_fact_id: fact.id,
            }));
        }
        Ok(output)
    }
}

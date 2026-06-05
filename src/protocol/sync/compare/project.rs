//! Poc-10 sync compare projector.
//!
//! POLICY. A sync_compare fact is admitted iff:
//!   1. STRUCTURAL. The compare payload decodes with its range summary.
//!   2. CONTEXT. No matched context is required; this is a peer summary.
//!   3. MATERIALIZE. Write the compare row and emit deferred compare work. The
//!      handler decides whether this row answers a peer request or continues a
//!      response round.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::sync::send_compare_response::{
    send_sync_compare_response_intent, SendSyncCompareResponse,
};

use super::sync_compare_row;

/// Staged read pipeline for the compare fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "sync::compare::Codec",
    authenticate: "sync::compare::authenticate::SyncCompareAuthenticator",
    adapt: "sync::compare::adapt::SyncCompareAdapter",
    project: "sync::compare::project::SyncCompareProjector",
};

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
        project_staged::<
            super::Codec,
            super::authenticate::SyncCompareAuthenticator,
            super::adapt::SyncCompareAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::SyncCompareFact> for SyncCompareProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        compare: super::fact::SyncCompareFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(sync_compare_row(fact.id, &compare)?))
            .intent(send_sync_compare_response_intent(SendSyncCompareResponse {
                compare_fact_id: fact.id,
            })))
    }
}

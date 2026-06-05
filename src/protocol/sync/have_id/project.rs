//! Poc-10 sync have-id projector.
//!
//! POLICY. A sync_have_id fact is admitted iff:
//!   1. STRUCTURAL. The advertisement payload decodes.
//!   2. CONTEXT. No matched context is required; idempotent handler work decides
//!      whether the advertised id is already present.
//!   3. MATERIALIZE. Write the have-id row and emit deferred need-id work.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::sync::send_needed_fact_id::{send_needed_fact_id_intent, SendNeededFactId};

use super::sync_have_id_row;

/// Staged read pipeline for the have_id fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "sync::have_id::Codec",
    authenticate: "sync::have_id::authenticate::SyncHaveIdAuthenticator",
    adapt: "sync::have_id::adapt::SyncHaveIdAdapter",
    project: "sync::have_id::project::SyncHaveIdProjector",
};

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
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::SyncHaveIdAuthenticator,
            super::adapt::SyncHaveIdAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::SyncHaveIdFact> for SyncHaveIdProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        have: super::fact::SyncHaveIdFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(sync_have_id_row(fact.id, &have)?))
            .intent(send_needed_fact_id_intent(SendNeededFactId {
                have_fact_id: fact.id,
            })))
    }
}

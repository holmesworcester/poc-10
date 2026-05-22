//! Poc-10 sync have-id projector.
//!
//! POLICY. A sync_have_id fact is admitted iff:
//!   1. STRUCTURAL. The advertisement payload decodes.
//!   2. CONTEXT. No matched context is required; idempotent handler work decides
//!      whether the advertised id is already present.
//!   3. MATERIALIZE. Write the have-id row and emit deferred need-id work.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::sync::send_needed_fact_id::{send_needed_fact_id_intent, SendNeededFactId};

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
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for SyncHaveIdProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        have: super::fact::SyncHaveIdFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(sync_have_id_row(fact.id, &have)?))
            .intent(send_needed_fact_id_intent(SendNeededFactId {
                have_fact_id: fact.id,
            })))
    }
}

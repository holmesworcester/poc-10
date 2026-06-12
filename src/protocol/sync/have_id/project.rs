//! Poc-10 sync have-id projector.
//!
//! POLICY. A sync_have_id fact is admitted iff:
//!   1. STRUCTURAL. The advertisement payload decodes.
//!   2. CONTEXT. No matched context is required; idempotent handler work decides
//!      whether the advertised id is already present.
//!   3. MATERIALIZE. Write the have-id row and emit deferred need-id work.
//!
//! Replay keeps this retained negotiation fact as evidence but does not rebuild
//! stale need/have state.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::sync::send_needed_fact_id::{send_needed_fact_id_intent, SendNeededFactId};

use super::sync_have_id_row;

/// Projector route metadata for the have_id fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("sync::have_id::project::SyncHaveIdProjector");

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
        let decoded = super::decode::decode_fact(fact.body())?;
        let authenticated = super::authenticate::authenticate(fact, decoded, context)?;
        let semantic = super::adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl SyncHaveIdProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        have: super::fact::SyncHaveIdFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(sync_have_id_row(fact.id, &have)?))
            .intent(send_needed_fact_id_intent(SendNeededFactId {
                have_fact_id: fact.id,
            })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionMode;
    use crate::protocol::sync::send_needed_fact_id::SEND_NEEDED_FACT_ID;

    #[test]
    fn replay_projection_does_not_rebuild_sync_negotiation_state() {
        let fact = Fact::new(FactScope::Local, 1, vec![1]);
        let have = super::super::fact::SyncHaveIdFact {
            connection_id: [2; 32],
            timestamp: 3,
            fact_id: [4; 32],
        };

        let live = SyncHaveIdProjector::new()
            .project_semantic(&fact, have, &ProjectionContext::default())
            .expect("live have-id projection");
        assert!(live
            .effects
            .intents
            .iter()
            .any(|intent| intent.kind.as_str() == SEND_NEEDED_FACT_ID));

        let replayed = SyncHaveIdProjector::new()
            .project_semantic(
                &fact,
                have,
                &ProjectionContext::default().with_mode(ProjectionMode::Replay),
            )
            .expect("replay have-id projection");
        assert!(replayed.effects.row_mutations.is_empty());
        assert!(replayed.effects.intents.is_empty());
    }
}

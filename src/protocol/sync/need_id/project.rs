//! Poc-10 sync need-id projector.
//!
//! POLICY. A sync_need_id fact is admitted iff:
//!   1. STRUCTURAL. The request payload decodes.
//!   2. CONTEXT. No matched context is required; idempotent handler work decides
//!      whether this store can answer.
//!   3. MATERIALIZE. Write the need-id row and emit deferred send-requested-fact
//!      work.
//!
//! Replay keeps this retained negotiation fact as evidence but does not rebuild
//! stale need/have state.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::sync::send_requested_fact::{send_requested_fact_intent, SendRequestedFact};

use super::sync_need_id_row;

/// Staged read pipeline for the need_id fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "sync::need_id::Codec",
    authenticate: "sync::need_id::authenticate::SyncNeedIdAuthenticator",
    adapt: "sync::need_id::adapt::SyncNeedIdAdapter",
    project: "sync::need_id::project::SyncNeedIdProjector",
};

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
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::SyncNeedIdAuthenticator,
            super::adapt::SyncNeedIdAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::SyncNeedIdFact> for SyncNeedIdProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        need: super::fact::SyncNeedIdFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(sync_need_id_row(fact.id, &need)?))
            .intent(send_requested_fact_intent(SendRequestedFact {
                need_fact_id: fact.id,
            })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::ProjectionMode;
    use crate::protocol::sync::send_requested_fact::SEND_REQUESTED_FACT;

    #[test]
    fn replay_projection_does_not_rebuild_sync_negotiation_state() {
        let fact = Fact::new(FactScope::Local, 1, vec![1]);
        let need = super::super::fact::SyncNeedIdFact {
            connection_id: [2; 32],
            fact_id: [3; 32],
        };

        let live = SyncNeedIdProjector::new()
            .project_semantic(&fact, need, &ProjectionContext::default())
            .expect("live need-id projection");
        assert!(live
            .effects
            .intents
            .iter()
            .any(|intent| intent.kind.as_str() == SEND_REQUESTED_FACT));

        let replayed = SyncNeedIdProjector::new()
            .project_semantic(
                &fact,
                need,
                &ProjectionContext::default().with_mode(ProjectionMode::Replay),
            )
            .expect("replay need-id projection");
        assert!(replayed.effects.row_mutations.is_empty());
        assert!(replayed.effects.intents.is_empty());
    }
}

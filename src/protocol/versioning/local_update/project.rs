//! Projection for local protocol update facts.
//!
//! Live projection calls `version_replay_rebuild`, records protocol-visible
//! update history, and advances the schema-declared protocol marker. That core
//! effect wipes resettable derived/runtime tables and replays retained facts.
//! Replay projection exits on `context.is_replay()` so old update facts remain
//! audit history without rerunning the wipe/replay.

use crate::core::effects::StorageRequirement;
use crate::core::facts::{Fact, FactScope};
use crate::core::project_fact::{
    verify_fact_id, FactProjectorInfo, ProjectedRowMutation, ProjectionContext, ProjectionOutput,
    Projector,
};

use super::fact::UpdateFact;
use super::protocol_version_row;

pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("versioning::local_update::project::UpdateProjector");

pub const STORAGE_REQUIREMENT: StorageRequirement = StorageRequirement::MaintenanceBypass;

#[derive(Debug, Default)]
pub struct UpdateProjector;

impl UpdateProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UpdateProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let update = adapt::adapt(authenticated, context)?;

        // POLICY. Update facts are local release-marker records. Live
        // projection performs the version-upgrade wipe/replay; replay keeps old
        // update facts as history without rerunning it.
        // 1. Replayed update facts do not materialize or request wipe/replay.
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }

        // 2. Live update facts record the marker and ask core to wipe
        // resettable derived/runtime state, then replay retained facts.
        Ok(ProjectionOutput::new()
            .version_replay_rebuild()
            .row_mutation(ProjectedRowMutation::InsertValues(protocol_version_row(
                fact.id, &update,
            ))))
    }
}

pub mod decode {
    use super::UpdateFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<UpdateFact, String> {
        super::super::encode::decode_update_fact(bytes)
    }
}

pub mod authenticate {
    use super::{verify_fact_id, Fact, FactScope, ProjectionContext, UpdateFact};

    pub fn authenticate(
        fact: &Fact,
        decoded: UpdateFact,
        _context: &ProjectionContext,
    ) -> Result<UpdateFact, String> {
        verify_fact_id(fact)?;
        if fact.scope != FactScope::Local {
            return Err("versioning update must be a local fact".to_string());
        }
        Ok(decoded)
    }
}

pub mod adapt {
    use super::{ProjectionContext, UpdateFact};

    pub fn adapt(update: UpdateFact, _context: &ProjectionContext) -> Result<UpdateFact, String> {
        Ok(update)
    }
}

pub fn authenticate(
    fact: &Fact,
    decoded: UpdateFact,
    context: &ProjectionContext,
) -> Result<UpdateFact, String> {
    authenticate::authenticate(fact, decoded, context)
}

// Tests. Ordered most-central-first: the broadest exercise of this file's core logic leads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::versioning::local_update::{author::update_fact, fact::UpdateFact};

    #[test]
    fn projector_records_version_and_requests_version_replay_rebuild_only_live() {
        let fact = update_fact(UpdateFact {
            protocol_version: crate::protocol::versioning::CURRENT_PROTOCOL_VERSION,
            applied_at_ms: 44,
        })
        .expect("update fact");
        let live = UpdateProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project live update");
        assert!(live.effects.version_replay_rebuild);
        assert_eq!(live.row_mutations.len(), 1);

        let replay = UpdateProjector::new()
            .project(
                &fact,
                &ProjectionContext::default()
                    .with_mode(crate::core::project_fact::ProjectionMode::Replay),
            )
            .expect("project replay update");
        assert!(replay.effects.is_empty());
    }
}

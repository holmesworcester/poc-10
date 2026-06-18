//! Projection for local protocol update facts.

use crate::core::db::{TableInsert, Value};
use crate::core::effects::StorageRequirement;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::project_fact::{
    verify_fact_id, FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use super::encode::decode_update_fact;
use super::fact::UpdateFact;
use super::PROTOCOL_VERSION_TABLE;

pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("versioning::update::UpdateProjector");

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
        let update = authenticate(fact, decode_update_fact(fact.body())?, context)?;
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }

        Ok(ProjectionOutput::new()
            .rebuild_derived_state()
            .row_mutation(crate::core::intents::RowMutation::InsertValues(
                version_row(fact.id, update),
            )))
    }
}

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

pub fn version_row(update_fact_id: FactId, update: UpdateFact) -> TableInsert {
    PROTOCOL_VERSION_TABLE.insert(vec![
        Value::Bytes(update_fact_id.to_vec()),
        Value::U64(u64::from(update.protocol_version)),
        Value::U64(update.applied_at_ms),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::FnClock;
    use crate::protocol::versioning::update::api::author_update;

    #[test]
    fn projector_records_version_and_requests_rebuild_only_live() {
        let output = author_update(&FnClock(|| 44)).expect("author update");
        let (_receipt, facts) = output.into_parts();
        let fact = &facts[0];
        let live = UpdateProjector::new()
            .project(fact, &ProjectionContext::default())
            .expect("project live update");
        assert!(live.effects.rebuild_derived_state);
        assert_eq!(live.effects.row_mutations.len(), 1);

        let replay = UpdateProjector::new()
            .project(
                fact,
                &ProjectionContext::default()
                    .with_mode(crate::core::project_fact::ProjectionMode::Replay),
            )
            .expect("project replay update");
        assert!(replay.effects.is_empty());
    }
}

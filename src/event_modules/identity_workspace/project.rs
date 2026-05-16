//! Poc-10 workspace projector.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_matchers;

use super::layout;
use super::rows::workspace_row;

#[derive(Debug, Clone, Default)]
pub struct WorkspaceProjector;

impl WorkspaceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for WorkspaceProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("workspace fact must have global scope".to_string());
        }
        let workspace = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .offer(identity_matchers::workspace_offer(fact.id))
            .intent(AtomicIntent::PutRow(workspace_row(fact.id, &workspace)?).into_intent()))
    }
}

//! Poc-10 workspace projector.
//!
//! POLICY. A workspace fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global and the workspace payload decodes.
//!   2. CONTEXT. No authority context is required; the workspace is the root
//!      identity object for later grants.
//!   3. MATERIALIZE. Write the workspace row, publish workspace context, and
//!      mark the workspace fact shareable with itself.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::sync::shared_fact::project::share_fact_with_sync;

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
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for WorkspaceProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        workspace: super::fact::WorkspaceFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("workspace fact must have global scope".to_string());
        }
        super::layout::verify_signature(&workspace)?;
        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "auth_workspace",
                    crate::core::facts::FactScope::Global,
                    fact.id,
                    fact.id,
                ))
                .row_mutation(RowMutation::PutRow(workspace_row(fact.id, &workspace)?)),
            fact.id,
            fact,
            Vec::new(),
        ))
    }
}

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::protocol::auth::workspace::create;
    use std::collections::BTreeSet;

    #[test]
    fn workspace_projector_emits_sync_share_contribution() {
        let fact = create::create_workspace(123_000, [9; 32], "Runtime").expect("workspace fact");
        let projected = WorkspaceProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project workspace");

        let intent_kinds = projected
            .effects
            .intents
            .iter()
            .map(|intent| intent.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(intent_kinds, BTreeSet::from(["share_fact_with_sync"]));
    }
}

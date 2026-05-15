//! Poc-10 removal frontier projector.
//!
//! Decodes the workspace-scoped fact body, validates fact metadata against the
//! payload, and emits a single `PutRow` atomic intent. The legacy projector
//! also walked signed-envelope and admin dependencies; those checks are
//! deferred until the target tree gains signed-envelope and admin projectors
//! (Wave 6 reconciliation).

use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::removal_frontier_row;

pub const WORKSPACE_SCOPE_KIND: &str = "workspace";

#[derive(Debug, Clone, Default)]
pub struct RemovalFrontierProjector;

impl RemovalFrontierProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for RemovalFrontierProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let frontier = layout::decode_fact(&fact.bytes)?;
        let expected_scope = FactScope::Scoped {
            kind: ScopeKind::new(WORKSPACE_SCOPE_KIND).map_err(|err| err.to_string())?,
            id: frontier.workspace_id,
        };
        if fact.scope != expected_scope {
            return Err("removal frontier fact scope does not match workspace_id".to_string());
        }
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(removal_frontier_row(fact.id, &frontier)?).into_intent()))
    }
}

//! Projector for sync shared-fact offers.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::protocol::facts::sync::encrypted_root::project::require_fact_scope;
use crate::protocol::matchers;

use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SyncSharedFactProjector;

impl SyncSharedFactProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncSharedFactProjector {
    fn project(
        &self,
        fact: &Fact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let shared = layout::decode_fact(fact.body())?;
        let scope = matchers::workspace_scope(shared.workspace_id);
        require_fact_scope(fact, &scope)?;
        Ok(ProjectionOutput::new().offer(matchers::exact_fact_offer(
            fact.id,
            scope,
            shared.fact_id,
            fact.id,
        )))
    }
}

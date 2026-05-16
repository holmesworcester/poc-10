//! Projector for sync shared-event offers.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::sync::matchers;
use crate::event_modules::sync_encrypted_root::project::require_fact_scope;

use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SyncSharedEventProjector;

impl SyncSharedEventProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncSharedEventProjector {
    fn project(
        &self,
        fact: &Fact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let shared = layout::decode_fact(&fact.bytes)?;
        let scope = matchers::workspace_scope(shared.workspace_id);
        require_fact_scope(fact, &scope)?;
        Ok(ProjectionOutput::new().offer(matchers::exact_event_offer(
            fact.id,
            scope,
            shared.event_id,
            fact.id,
        )))
    }
}

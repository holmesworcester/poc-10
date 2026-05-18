//! Projector for sync key-wrap availability offers.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::sync::matchers;
use crate::event_modules::sync_encrypted_root::project::require_fact_scope;

use super::layout;

#[derive(Debug, Clone, Default)]
pub struct SyncKeyWrapAvailableProjector;

impl SyncKeyWrapAvailableProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncKeyWrapAvailableProjector {
    fn project(
        &self,
        fact: &Fact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let key = layout::decode_fact(&fact.bytes)?;
        let scope = matchers::workspace_scope(key.workspace_id);
        require_fact_scope(fact, &scope)?;
        Ok(ProjectionOutput::new()
            .offer(matchers::exact_event_offer(
                fact.id,
                scope.clone(),
                key.key_wrap_id,
            ))
            .offer(matchers::key_wrap_offer(fact.id, scope, key.key_wrap_id)))
    }
}

//! Projector for sync key-wrap availability offers.
//!
//! POLICY. A sync key_wrap_available fact is admitted iff:
//!   1. STRUCTURAL. The body decodes and the outer fact scope matches its
//!      workspace id.
//!   2. CONTEXT. No incoming context is required; the fact advertises that the
//!      named key wrap is available locally.
//!   3. MATERIALIZE. Publish exact-fact and key-wrap offers for range-request
//!      dependency matching.

use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::facts::sync::encrypted_root::project::require_fact_scope;

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
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for SyncKeyWrapAvailableProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        key: super::fact::KeyWrapAvailableFact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::facts::identity::workspace::scope(key.workspace_id);
        require_fact_scope(fact, &scope)?;
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "sync_exact_fact",
                scope.clone(),
                key.key_wrap_id,
                key.key_wrap_id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "sync_key_wrap",
                scope,
                key.key_wrap_id,
                key.key_wrap_id,
            )))
    }
}

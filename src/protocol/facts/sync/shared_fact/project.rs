//! Projector for sync shared-fact offers.
//!
//! POLICY. A sync shared_fact is admitted iff:
//!   1. STRUCTURAL. The body decodes and the outer fact scope matches its
//!      workspace id.
//!   2. CONTEXT. No incoming context is required; this fact advertises a shared
//!      payload id that is already present.
//!   3. MATERIALIZE. Publish an exact-fact offer for range-request dependency
//!      matching.

use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::context_keys;
use crate::protocol::facts::sync::encrypted_root::project::require_fact_scope;

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
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for SyncSharedFactProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        shared: super::fact::SharedFact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = context_keys::workspace_scope(shared.workspace_id);
        require_fact_scope(fact, &scope)?;
        // 3. Materialize.
        Ok(
            ProjectionOutput::new().offer(context_keys::exact_fact_offer(
                fact.id,
                scope,
                shared.fact_id,
            )),
        )
    }
}

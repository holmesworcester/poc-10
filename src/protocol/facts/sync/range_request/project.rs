//! Projector for sync range requests.
//!
//! POLICY. A sync range_request fact is admitted iff:
//!   1. STRUCTURAL. The request payload decodes and its fact scope matches the
//!      requested workspace.
//!   2. MATERIALIZE. Range matching is currently disabled; full-range connect
//!      sync and progressive send own transfer until subrange sync is real again.

use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::facts::sync::encrypted_root::project as encrypted_root_project;

#[derive(Debug, Clone, Default)]
pub struct SyncRangeRequestProjector;

impl SyncRangeRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncRangeRequestProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for SyncRangeRequestProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        request: super::fact::SyncRangeRequestFact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::facts::identity::workspace::scope(request.workspace_id);
        encrypted_root_project::require_fact_scope(fact, &scope)?;

        // 2. Materialize.
        Ok(ProjectionOutput::new())
    }
}

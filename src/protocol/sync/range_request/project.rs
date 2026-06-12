//! Projector for sync range requests.
//!
//! POLICY. A sync range_request fact is admitted iff:
//!   1. STRUCTURAL. The request payload decodes and its fact scope matches the
//!      requested workspace.
//!   2. MATERIALIZE. The fact records no rows; full-range connect sync and
//!      progressive send own transfer for this protocol slice.

use crate::core::facts::{Fact, FactScope};
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};

/// Projector route metadata for the range_request fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("sync::range_request::project::SyncRangeRequestProjector");

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
        let decoded = super::decode::decode_fact(fact.body())?;
        let authenticated = super::authenticate::authenticate(fact, decoded, projection_context)?;
        let semantic = super::adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, projection_context)
    }
}

impl SyncRangeRequestProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        request: super::fact::SyncRangeRequestFact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let scope = crate::protocol::auth::workspace::scope(request.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Materialize.
        Ok(ProjectionOutput::new())
    }
}

fn require_fact_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context fact scope does not match body workspace".to_string())
    }
}

//! Projector for sync range requests.
//!
//! POLICY. A sync range_request fact is admitted iff:
//!   1. STRUCTURAL. The request payload decodes and its fact scope matches the
//!      requested workspace.
//!   2. MATERIALIZE. The fact records no rows; full-range connect sync and
//!      progressive send own transfer for this protocol slice.

use crate::core::facts::{Fact, FactScope};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

/// Staged read pipeline for the range_request fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "sync::range_request::Codec",
    authenticate: "sync::range_request::authenticate::SyncRangeRequestAuthenticator",
    adapt: "sync::range_request::adapt::SyncRangeRequestAdapter",
    project: "sync::range_request::project::SyncRangeRequestProjector",
};

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
        project_staged::<
            super::Codec,
            super::authenticate::SyncRangeRequestAuthenticator,
            super::adapt::SyncRangeRequestAdapter,
            _,
        >(self, fact, projection_context)
    }
}

impl SemanticProjector<super::fact::SyncRangeRequestFact> for SyncRangeRequestProjector {
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

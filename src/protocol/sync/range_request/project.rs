//! Projector for sync range requests.
//!
//! POLICY. A sync range_request fact is admitted iff:
//!   1. STRUCTURAL. The request payload decodes and its fact scope matches the
//!      requested workspace.
//!   2. MATERIALIZE. The fact records no rows; full-range connect sync and
//!      progressive send own transfer for this protocol slice.

use crate::core::facts::{Fact, FactScope};
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
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
        project_authenticated::<super::authenticate::SyncRangeRequestAuthenticator, _>(
            self,
            fact,
            projection_context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::SyncRangeRequestAuthenticator>
    for SyncRangeRequestProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::SyncRangeRequestFact>,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, request) = authenticated.into_parts();
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

//! Connection-frame observation projector.
//!
//! POLICY. A `connection_frame_observation` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and its payload names one frame fact
//!      plus canonical receive metadata.
//!   2. CONTEXT. No external authority is loaded; the matching frame projector
//!      validates and opens the frame bytes.
//!   3. MATERIALIZE. Publish local `connection_frame_observation` context keyed
//!      by the observed frame fact id.

use crate::core::context::ContextOffer;
use crate::core::facts::{Fact, FactScope};
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use super::fact::ConnectionFrameObservationFact;

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameObservationProjector;

impl ConnectionFrameObservationProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameObservationProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionFrameObservationAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionFrameObservationAuthenticator>
    for ConnectionFrameObservationProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionFrameObservationFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, observed) = authenticated.into_parts();
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection frame observation must have local scope".to_string());
        }

        // 2. Context.
        // 3. Materialize.
        Ok(ProjectionOutput::new().offer(ContextOffer::range(
            fact.id,
            "connection_frame_observation",
            FactScope::Local,
            observed.frame_fact_id,
            observed.frame_fact_id,
        )))
    }
}

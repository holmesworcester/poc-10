//! Bundled connection-frame projector.
//!
//! POLICY. A `connection_frame_bundle` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local ephemeral input and its layout contains
//!      exactly one bundled encrypted connection frame.
//!   2. CONTEXT. The frame fact has exact local `connection_frame_observation`
//!      context, and its header names an exact local `connection_established`
//!      context. Missing context emits only a transient need for the fixed-point
//!      pass; malformed and undecryptable frames produce no durable output.
//!   3. MATERIALIZE. Opened inner facts are admitted as durable child facts,
//!      each with a durable `connection::fact_receipt`.

use crate::core::facts::Fact;
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use super::create;
use super::fact::ConnectionFrameBundleFact;

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameBundleProjector;

impl ConnectionFrameBundleProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameBundleProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionFrameBundleAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionFrameBundleAuthenticator>
    for ConnectionFrameBundleProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionFrameBundleFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, input) = authenticated.into_parts();
        // 1. Structural.
        // 2. Context.
        // 3. Materialize.
        create::project_observed_frame(fact, input, context)
    }
}

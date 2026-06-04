//! Bootstrap request-received projector.
//!
//! This local lifecycle fact records that a sealed bootstrap request reached
//! this endpoint and was accepted far enough for responder work.
//!
//! POLICY. A bootstrap_request_received is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and authentication proved its ids
//!      are non-empty.
//!   2. CONTEXT. No additional context is needed; the bootstrap request
//!      projector creates it only after proving receipt and endpoint context.
//!   3. MATERIALIZE. Valid facts offer request-received context for audit and
//!      downstream joins. They do not create network work directly.
//!
//! Change this projector for responder-side bootstrap request lifecycle
//! context. Request admission and response authoring stay in
//! `bootstrap_request::project` and `create_bootstrap_response`.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use super::fact::BootstrapRequestReceivedFact;

const BOOTSTRAP_REQUEST_RECEIVED_ROLE: &str = "bootstrap_request_received";

pub fn bootstrap_request_received_offer(
    owner: [u8; 32],
    request_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        BOOTSTRAP_REQUEST_RECEIVED_ROLE,
        FactScope::Local,
        request_id,
        request_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct BootstrapRequestReceivedProjector;

impl BootstrapRequestReceivedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for BootstrapRequestReceivedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::BootstrapRequestReceivedAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::BootstrapRequestReceivedAuthenticator>
    for BootstrapRequestReceivedProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, BootstrapRequestReceivedFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, received) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("bootstrap_request_received fact must be local".to_string());
        }
        // 3. Materialize request-received lifecycle context.
        Ok(
            ProjectionOutput::new().offer(bootstrap_request_received_offer(
                fact.id,
                received.request_id,
            )),
        )
    }
}

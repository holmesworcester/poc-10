//! Membership connection-request-received projector.
//!
//! This local lifecycle fact records that a sealed membership request reached
//! this endpoint through the network receive boundary and was accepted far
//! enough for the request projector to emit responder work.
//!
//! POLICY. A connection_request_received is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and authentication proved its
//!      request and receive ids are non-empty.
//!   2. CONTEXT. This projector has no additional context dependency; the
//!      protocol `connection_request` projector created it only after proving
//!      the frame observation, receipt, local endpoint, and membership context.
//!   3. MATERIALIZE. Valid facts offer request-received context for local
//!      audit and downstream joins. They do not create network work directly.
//!
//! Change this projector for responder-side request lifecycle context. Request
//! authentication and response authoring belong in `connection_request::project`
//! and `create_connection_response`.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use super::fact::ConnectionRequestReceivedFact;

const MEMBERSHIP_CONNECTION_REQUEST_RECEIVED_ROLE: &str = "membership_connection_request_received";

pub fn connection_request_received_offer(
    owner: [u8; 32],
    request_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        MEMBERSHIP_CONNECTION_REQUEST_RECEIVED_ROLE,
        FactScope::Local,
        request_id,
        request_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestReceivedProjector;

impl ConnectionRequestReceivedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestReceivedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionRequestReceivedAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionRequestReceivedAuthenticator>
    for ConnectionRequestReceivedProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionRequestReceivedFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, received) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection_request_received fact must be local".to_string());
        }
        // 3. Materialize request-received lifecycle context.
        Ok(
            ProjectionOutput::new().offer(connection_request_received_offer(
                fact.id,
                received.request_id,
            )),
        )
    }
}

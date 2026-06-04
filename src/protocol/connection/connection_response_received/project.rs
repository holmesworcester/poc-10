//! Membership connection-response-received projector.
//!
//! This local lifecycle fact records that a sealed membership response reached
//! the initiator through the network receive boundary and was accepted far
//! enough for the response projector to derive connection material.
//!
//! POLICY. A connection_response_received is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and authentication proved its
//!      response, request, and receive ids are non-empty.
//!   2. CONTEXT. This projector has no additional context dependency; the
//!      protocol `connection_response` projector created it only after proving
//!      request-sent context, frame observation, receipt, and initiator secret.
//!   3. MATERIALIZE. Valid facts offer response-received context for local
//!      audit and downstream joins. Connection rows are written by
//!      `connection_established`.
//!
//! Change this projector for initiator-side response lifecycle context. Response
//! opening and connection derivation belong in `connection_response::project`.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use super::fact::ConnectionResponseReceivedFact;

const MEMBERSHIP_CONNECTION_RESPONSE_RECEIVED_ROLE: &str =
    "membership_connection_response_received";

pub fn connection_response_received_offer(
    owner: [u8; 32],
    response_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        MEMBERSHIP_CONNECTION_RESPONSE_RECEIVED_ROLE,
        FactScope::Local,
        response_id,
        response_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionResponseReceivedProjector;

impl ConnectionResponseReceivedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionResponseReceivedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionResponseReceivedAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionResponseReceivedAuthenticator>
    for ConnectionResponseReceivedProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionResponseReceivedFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, received) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection_response_received fact must be local".to_string());
        }
        // 3. Materialize response-received lifecycle context.
        Ok(
            ProjectionOutput::new().offer(connection_response_received_offer(
                fact.id,
                received.response_id,
            )),
        )
    }
}

//! Membership connection-response-sent projector.
//!
//! This local lifecycle fact records the responder-side durable evidence for a
//! sealed membership response and owns the network send for the exact sealed
//! response bytes.
//!
//! POLICY. A connection_response_sent is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and authentication proved the
//!      response id matches the sealed response bytes.
//!   2. CONTEXT. This projector has no additional context dependency; the
//!      response command created it only after opening the request and deriving
//!      responder connection material.
//!   3. MATERIALIZE. Valid facts offer response-sent context and emit the
//!      local send_network_frame intent keyed by this lifecycle fact.
//!
//! Change this projector for responder-side response lifecycle or network-send
//! ownership. Response wire compatibility belongs in
//! `connection_response::layout`.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame,
};

use super::fact::ConnectionResponseSentFact;

const MEMBERSHIP_CONNECTION_RESPONSE_SENT_ROLE: &str = "membership_connection_response_sent";

pub fn connection_response_sent_offer(
    owner: [u8; 32],
    response_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        MEMBERSHIP_CONNECTION_RESPONSE_SENT_ROLE,
        FactScope::Local,
        response_id,
        response_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionResponseSentProjector;

impl ConnectionResponseSentProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionResponseSentProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionResponseSentAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionResponseSentAuthenticator>
    for ConnectionResponseSentProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionResponseSentFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, sent) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection_response_sent fact must be local".to_string());
        }
        // 3. Materialize response-sent lifecycle and send sealed response bytes.
        Ok(ProjectionOutput::new()
            .offer(connection_response_sent_offer(fact.id, sent.response_id))
            .local_intent(send_network_frame_intent(SendNetworkFrame {
                routing_key: fact.id,
                frame: sent.sealed_response_bytes.to_vec(),
            })))
    }
}

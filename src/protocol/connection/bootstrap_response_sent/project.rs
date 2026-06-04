//! Bootstrap response-sent projector.
//!
//! This local lifecycle fact records a responder-authored bootstrap response and
//! owns the network send for its exact sealed response bytes.
//!
//! POLICY. A bootstrap_response_sent is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and authentication proved the
//!      response id matches the semantic response bytes.
//!   2. CONTEXT. No additional context is needed; the response handler created
//!      this fact after proving request, invite, receive, and endpoint context.
//!   3. MATERIALIZE. Valid facts offer response-sent context and emit the
//!      local send_network_frame intent keyed by this lifecycle fact.
//!
//! Change this projector for responder-side bootstrap response lifecycle or
//! send ownership. Response bytes belong in `bootstrap_response::layout` and
//! transit sealing belongs in `bootstrap_response::transit`.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame,
};

use super::fact::BootstrapResponseSentFact;

const BOOTSTRAP_RESPONSE_SENT_ROLE: &str = "bootstrap_response_sent";

pub fn bootstrap_response_sent_offer(
    owner: [u8; 32],
    response_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        BOOTSTRAP_RESPONSE_SENT_ROLE,
        FactScope::Local,
        response_id,
        response_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct BootstrapResponseSentProjector;

impl BootstrapResponseSentProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for BootstrapResponseSentProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::BootstrapResponseSentAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::BootstrapResponseSentAuthenticator>
    for BootstrapResponseSentProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, BootstrapResponseSentFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, sent) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("bootstrap_response_sent fact must be local".to_string());
        }
        // 3. Materialize response-sent lifecycle and send sealed response bytes.
        Ok(ProjectionOutput::new()
            .offer(bootstrap_response_sent_offer(fact.id, sent.response_id))
            .local_intent(send_network_frame_intent(SendNetworkFrame {
                routing_key: fact.id,
                frame: sent.sealed_response_bytes.to_vec(),
            })))
    }
}

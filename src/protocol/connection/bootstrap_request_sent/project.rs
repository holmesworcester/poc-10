//! Bootstrap request-sent projector.
//!
//! This local lifecycle fact records an outbound sealed bootstrap request and
//! owns the retry row used by live connection maintenance.
//!
//! POLICY. A bootstrap_request_sent is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and authentication proved the request
//!      id matches the semantic request bytes.
//!   2. CONTEXT. This projector has no extra context dependency; the authoring
//!      command created the invite secret, ephemeral secret, request body, and
//!      sealed bytes atomically.
//!   3. MATERIALIZE. Valid facts offer request-sent context, write the pending
//!      bootstrap request row, and remember the peer endpoint address.
//!
//! Change this projector for outbound bootstrap retry routing. Request byte
//! compatibility belongs in `bootstrap_request::layout` and transit sealing in
//! `bootstrap_request::transit`.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::connection::bootstrap_request::rows::bootstrap_request_row;
use crate::protocol::connection::observed_endpoint_address::rows::observed_endpoint_address_row;

use super::fact::BootstrapRequestSentFact;

const BOOTSTRAP_REQUEST_SENT_ROLE: &str = "bootstrap_request_sent";

pub fn bootstrap_request_sent_need(
    owner: [u8; 32],
    request_id: [u8; 32],
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        BOOTSTRAP_REQUEST_SENT_ROLE,
        FactScope::Local,
        request_id,
        request_id,
    )
}

pub fn bootstrap_request_sent_offer(
    owner: [u8; 32],
    request_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        BOOTSTRAP_REQUEST_SENT_ROLE,
        FactScope::Local,
        request_id,
        request_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct BootstrapRequestSentProjector;

impl BootstrapRequestSentProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for BootstrapRequestSentProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::BootstrapRequestSentAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::BootstrapRequestSentAuthenticator>
    for BootstrapRequestSentProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, BootstrapRequestSentFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, sent) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("bootstrap_request_sent fact must be local".to_string());
        }
        // 3. Materialize request-sent lifecycle and retry route.
        Ok(ProjectionOutput::new()
            .offer(bootstrap_request_sent_offer(fact.id, sent.request_id))
            .row_mutation(RowMutation::PutRow(bootstrap_request_row(
                sent.request_id,
                fact.id,
                &sent.request,
                Some(sent.peer_addr),
                &sent.sealed_request_bytes,
            )?))
            .row_mutation(RowMutation::PutRow(observed_endpoint_address_row(
                sent.request.to_endpoint,
                sent.peer_addr,
            )?)))
    }
}

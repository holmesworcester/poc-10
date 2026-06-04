//! Membership connection-request-sent projector.
//!
//! This local lifecycle fact records the sender-side durable evidence for a
//! sealed membership request: the private secret fact id it depends on, the
//! peer route, and the exact sealed bytes that go on the network.
//!
//! POLICY. A connection_request_sent is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and authentication proved the
//!      request id matches the sealed request bytes.
//!   2. CONTEXT. This projector has no additional context dependency; the
//!      authoring command already created the local ephemeral secret fact and
//!      sealed request atomically.
//!   3. MATERIALIZE. Valid facts offer request-sent context, write the pending
//!      membership request row for retry/send, and remember the peer endpoint
//!      address learned from the outgoing route.
//!
//! Change this projector for sender-side request lifecycle rows or retry
//! routing. Membership request wire compatibility belongs in
//! `connection_request::layout`.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::connection::connection_request::rows::connection_request_row;
use crate::protocol::connection::observed_endpoint_address::rows::observed_endpoint_address_row;

use super::fact::ConnectionRequestSentFact;

const MEMBERSHIP_CONNECTION_REQUEST_SENT_ROLE: &str = "membership_connection_request_sent";

pub fn connection_request_sent_need(
    owner: [u8; 32],
    request_id: [u8; 32],
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        MEMBERSHIP_CONNECTION_REQUEST_SENT_ROLE,
        FactScope::Local,
        request_id,
        request_id,
    )
}

pub fn connection_request_sent_offer(
    owner: [u8; 32],
    request_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        MEMBERSHIP_CONNECTION_REQUEST_SENT_ROLE,
        FactScope::Local,
        request_id,
        request_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestSentProjector;

impl ConnectionRequestSentProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestSentProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionRequestSentAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionRequestSentAuthenticator>
    for ConnectionRequestSentProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionRequestSentFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, sent) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection_request_sent fact must be local".to_string());
        }
        // 3. Materialize request-sent lifecycle and retry route.
        Ok(ProjectionOutput::new()
            .offer(connection_request_sent_offer(fact.id, sent.request_id))
            .row_mutation(RowMutation::PutRow(connection_request_row(
                sent.request_id,
                fact.id,
                sent.initiator_ephemeral_secret_fact_id,
                Some(sent.peer_addr),
                &sent.sealed_request_bytes,
            )?))
            .row_mutation(RowMutation::PutRow(observed_endpoint_address_row(
                sent.request.to_endpoint,
                sent.peer_addr,
            )?)))
    }
}

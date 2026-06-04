//! Membership connection-established projector.
//!
//! This local lifecycle fact is the symmetric endpoint state created by both
//! the responder's successful response authoring path and the initiator's
//! successful response receipt path.
//!
//! POLICY. A connection_established is admitted iff:
//!   1. STRUCTURAL. The fact is local-only, endpoints differ, and
//!      authentication proved all connection material fields are non-empty.
//!   2. CONTEXT. Projection watches for local close context keyed by the
//!      connection id; close context tears down the live row and purges this
//!      local state fact.
//!   3. MATERIALIZE. Valid facts offer connection-established and
//!      connection-response context, then write the live connection row used by
//!      encrypted frame send/receive. The fact carries no role; initiator or
//!      responder history is inferred from request/response lifecycle facts.
//!
//! Change this projector for established-connection row ownership or close
//! teardown. Handshake derivation belongs in response authoring/receipt paths.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{RowMutation, TableDelete};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::connection::bootstrap_response::rows::{
    bootstrap_response_key, connection_row, ConnectionRowFields, BOOTSTRAP_RESPONSE_ROWS,
};
use crate::protocol::connection::close;

use super::fact::ConnectionEstablishedFact;

const CONNECTION_ESTABLISHED_ROLE: &str = "connection_established";

pub fn connection_established_offer(
    owner: [u8; 32],
    connection_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        CONNECTION_ESTABLISHED_ROLE,
        FactScope::Local,
        connection_id,
        connection_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionEstablishedProjector;

impl ConnectionEstablishedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionEstablishedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionEstablishedAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionEstablishedAuthenticator>
    for ConnectionEstablishedProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionEstablishedFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, established) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection_established fact must be local".to_string());
        }
        // 2. Close context tears down the live connection row.
        let close_need = close::connection_closed_need(fact.id, established.connection_id);
        if let Some(close_fact) = context.payload_for(&close_need) {
            if close_fact.scope != FactScope::Local {
                return Err("connection_established close context must be local".to_string());
            }
            return Ok(ProjectionOutput::new()
                .row_mutation(RowMutation::DeleteRow(TableDelete {
                    table: BOOTSTRAP_RESPONSE_ROWS,
                    key: bootstrap_response_key(&established.connection_id),
                }))
                .purge_self(fact.id));
        }
        // 3. Materialize symmetric established-connection state.
        Ok(ProjectionOutput::new()
            .need(close_need)
            .offer(connection_established_offer(
                fact.id,
                established.connection_id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_response",
                FactScope::Local,
                established.connection_id,
                established.connection_id,
            ))
            .row_mutation(RowMutation::PutRow(connection_row(ConnectionRowFields {
                connection_id: established.connection_id,
                from_endpoint: established.from_endpoint,
                to_endpoint: established.to_endpoint,
                request_id: established.request_id,
                responder_ephemeral_public_key: established.responder_ephemeral_public_key,
                handshake_hash: established.handshake_hash,
                connection_secret: established.connection_secret,
            })?)))
    }
}

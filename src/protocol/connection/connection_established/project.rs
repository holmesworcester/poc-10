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
//!   3. MATERIALIZE. Valid facts offer connection-established context, then
//!      write the live connection row used by encrypted frame send/receive. The
//!      fact carries no role; initiator or responder history is inferred from
//!      request/response lifecycle facts.
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

pub fn connection_established_need(
    owner: [u8; 32],
    connection_id: [u8; 32],
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
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

#[cfg(test)]
mod projector_tests {
    use crate::core::context::ContextOffer;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use crate::protocol::connection::close;

    use super::*;

    fn established_fact() -> Fact {
        Fact::new(
            FactScope::Local,
            1_700_000_000,
            crate::protocol::connection::connection_established::layout::encode_fact(
                &ConnectionEstablishedFact {
                    connection_id: [1; 32],
                    from_endpoint: [2; 32],
                    to_endpoint: [3; 32],
                    request_id: [4; 32],
                    initiator_ephemeral_secret_fact_id: [5; 32],
                    responder_ephemeral_secret_fact_id: [6; 32],
                    responder_ephemeral_public_key: [7; 32],
                    handshake_hash: [8; 32],
                    connection_secret: [9; 32],
                    established_at_ms: 1_700_000_000,
                },
            )
            .expect("encode established"),
        )
    }

    #[test]
    fn established_connection_writes_live_row_and_offers_context() {
        let fact = established_fact();

        let output = ConnectionEstablishedProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project established");

        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role.as_str(), "connection_established");
        assert_eq!(output.effects.row_mutations.len(), 1);
        assert!(output.effects.intents.is_empty());
    }

    #[test]
    fn closed_connection_deletes_live_row_without_seeding_sync() {
        let fact = established_fact();
        let close_need = close::connection_closed_need(fact.id, [1; 32]);
        let close_fact = Fact::new(FactScope::Local, 1_700_000_001, vec![99]);
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: close_need.clone(),
            offer: ContextOffer {
                owner: close_fact.id,
                role: close_need.role.clone(),
                scope: FactScope::Local,
                start_key: close_need.start_key.clone(),
                end_key: close_need.end_key.clone(),
            },
            payload: close_fact,
        }]);

        let output = ConnectionEstablishedProjector::new()
            .project(&fact, &context)
            .expect("project closed established");

        assert!(output.offers.is_empty());
        assert_eq!(output.effects.row_mutations.len(), 1);
        assert_eq!(output.effects.purged_facts, vec![fact.id]);
        assert!(output.effects.intents.is_empty());
    }
}

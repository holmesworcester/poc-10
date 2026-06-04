//! Bootstrap response-received projector.
//!
//! This local lifecycle fact records that a sealed bootstrap response reached
//! the initiator and was accepted far enough to establish a connection.
//!
//! POLICY. A bootstrap_response_received is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and authentication proved its ids
//!      are non-empty.
//!   2. CONTEXT. No additional context is needed; the bootstrap response
//!      projector creates it only after proving request-sent, receipt, invite,
//!      and initiator secret context.
//!   3. MATERIALIZE. Valid facts offer response-received context for audit and
//!      downstream joins, then seed sync once matching `connection_established`
//!      context proves the live row exists.
//!
//! Change this projector for initiator-side bootstrap response lifecycle
//! context. Response admission stays in `bootstrap_response::project`.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::connection::connection_established;
use crate::protocol::sync::seed_connection::{seed_connection_sync_intent, SeedConnectionSync};

use super::fact::BootstrapResponseReceivedFact;

const BOOTSTRAP_RESPONSE_RECEIVED_ROLE: &str = "bootstrap_response_received";

pub fn bootstrap_response_received_offer(
    owner: [u8; 32],
    response_id: [u8; 32],
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        BOOTSTRAP_RESPONSE_RECEIVED_ROLE,
        FactScope::Local,
        response_id,
        response_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct BootstrapResponseReceivedProjector;

impl BootstrapResponseReceivedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for BootstrapResponseReceivedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::BootstrapResponseReceivedAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::BootstrapResponseReceivedAuthenticator>
    for BootstrapResponseReceivedProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, BootstrapResponseReceivedFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, received) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("bootstrap_response_received fact must be local".to_string());
        }
        let established_need = connection_established::project::connection_established_need(
            fact.id,
            received.response_id,
        );
        let output = ProjectionOutput::new()
            .offer(bootstrap_response_received_offer(
                fact.id,
                received.response_id,
            ))
            .need(established_need.clone());
        let Some(established_fact) = context.payload_for(&established_need) else {
            return Ok(output);
        };
        if established_fact.scope != FactScope::Local {
            return Err(
                "bootstrap_response_received established context must be local".to_string(),
            );
        }
        let established = connection_established::decode_fact_payload(established_fact.body())
            .map_err(|_| {
                "bootstrap_response_received context is not connection_established".to_string()
            })?;
        if established.connection_id != received.response_id {
            return Err(
                "bootstrap_response_received established context targets another response"
                    .to_string(),
            );
        }
        // 3. Materialize response-received lifecycle context.
        Ok(
            output.intent(seed_connection_sync_intent(SeedConnectionSync {
                connection_id: received.response_id,
            })),
        )
    }
}

#[cfg(test)]
mod projector_tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use crate::protocol::connection::connection_established::{
        fact::ConnectionEstablishedFact, layout as established_layout,
        project as established_project,
    };
    use crate::protocol::sync::seed_connection::decode_seed_connection_sync;

    use super::*;

    fn received_fact() -> Fact {
        Fact::new(
            FactScope::Local,
            20,
            crate::protocol::connection::bootstrap_response_received::layout::encode_fact(
                &BootstrapResponseReceivedFact {
                    response_id: [1; 32],
                    request_id: [2; 32],
                    receive_id: [3; 32],
                    received_at_local_ms: 20,
                },
            )
            .expect("encode received"),
        )
    }

    fn established_fact() -> Fact {
        Fact::new(
            FactScope::Local,
            20,
            established_layout::encode_fact(&ConnectionEstablishedFact {
                connection_id: [1; 32],
                from_endpoint: [4; 32],
                to_endpoint: [5; 32],
                request_id: [2; 32],
                initiator_ephemeral_secret_fact_id: [6; 32],
                responder_ephemeral_secret_fact_id: [7; 32],
                responder_ephemeral_public_key: [8; 32],
                handshake_hash: [9; 32],
                connection_secret: [10; 32],
                established_at_ms: 20,
            })
            .expect("encode established"),
        )
    }

    #[test]
    fn received_response_waits_for_established_context_before_seeding() {
        let fact = received_fact();

        let output = BootstrapResponseReceivedProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project received");

        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.needs.len(), 1);
        assert!(output.effects.intents.is_empty());
    }

    #[test]
    fn received_response_seeds_sync_after_established_context() {
        let fact = received_fact();
        let established = established_fact();
        let need = established_project::connection_established_need(fact.id, [1; 32]);
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need,
            offer: established_project::connection_established_offer(established.id, [1; 32]),
            payload: established,
        }]);

        let output = BootstrapResponseReceivedProjector::new()
            .project(&fact, &context)
            .expect("project received");

        assert_eq!(output.effects.intents.len(), 1);
        let seed =
            decode_seed_connection_sync(&output.effects.intents[0]).expect("decode seed intent");
        assert_eq!(seed.connection_id, [1; 32]);
    }
}

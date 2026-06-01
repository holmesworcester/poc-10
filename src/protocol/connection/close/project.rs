//! Connection-close projector.
//!
//! Close projection validates that a local close fact names a materialized
//! connection response. It then publishes close context keyed by the connection
//! id and by both ephemeral-secret fact ids carried by that response.
//!
//! POLICY. A connection_close is admitted iff:
//!   1. STRUCTURAL. The fact is local and names a non-empty connection id.
//!   2. CONTEXT. The exact local connection_response context for that id is
//!      present and decodes as the referenced response fact.
//!   3. MATERIALIZE. Publish close offers only; target facts own their own row
//!      deletion and self-purge when those offers wake them.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use crate::protocol::connection::bootstrap_response as response;

const CONNECTION_CLOSED_ROLE: &str = "connection_closed";
const CONNECTION_EPHEMERAL_SECRET_CLOSED_ROLE: &str = "connection_ephemeral_secret_closed";

pub fn connection_closed_need(owner: FactId, connection_id: FactId) -> ContextNeed {
    exact_local_need(owner, CONNECTION_CLOSED_ROLE, connection_id)
}

pub fn connection_closed_offer(owner: FactId, connection_id: FactId) -> ContextOffer {
    exact_local_offer(owner, CONNECTION_CLOSED_ROLE, connection_id)
}

pub fn ephemeral_secret_closed_need(owner: FactId, secret_id: FactId) -> ContextNeed {
    exact_local_need(owner, CONNECTION_EPHEMERAL_SECRET_CLOSED_ROLE, secret_id)
}

pub fn ephemeral_secret_closed_offer(owner: FactId, secret_id: FactId) -> ContextOffer {
    exact_local_offer(owner, CONNECTION_EPHEMERAL_SECRET_CLOSED_ROLE, secret_id)
}

fn exact_local_need(owner: FactId, role: &'static str, key: FactId) -> ContextNeed {
    let key = ContextKey::from_bytes(key);
    ContextNeed {
        owner,
        role: Role::expect(role),
        scope: FactScope::Local,
        start_key: key.clone(),
        end_key: key,
    }
}

fn exact_local_offer(owner: FactId, role: &'static str, key: FactId) -> ContextOffer {
    let key = ContextKey::from_bytes(key);
    ContextOffer {
        owner,
        role: Role::expect(role),
        scope: FactScope::Local,
        start_key: key.clone(),
        end_key: key,
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionCloseProjector;

impl ConnectionCloseProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionCloseProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionCloseAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionCloseAuthenticator>
    for ConnectionCloseProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::ConnectionCloseFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes and the
        // non-empty connection id. Scope is interpretation.
        let (fact, close) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection close fact must have local scope".to_string());
        }

        // 2. Context.
        let connection_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_response",
            FactScope::Local,
            close.connection_id,
            close.connection_id,
        );
        let Some(connection_fact) = context.payload_for(&connection_need) else {
            return Ok(ProjectionOutput::new().need(connection_need));
        };
        if connection_fact.id != close.connection_id {
            return Err("connection close context id does not match close".to_string());
        }
        if connection_fact.scope != FactScope::Local {
            return Err("connection close context must be local".to_string());
        }
        let connection = response::decode_fact_payload(connection_fact.body())
            .map_err(|_| "connection close context is not a connection response".to_string())?;

        // 3. Materialize close context for the target owners.
        Ok(ProjectionOutput::new()
            .need(connection_need)
            .offer(connection_closed_offer(fact.id, close.connection_id))
            .offer(ephemeral_secret_closed_offer(
                fact.id,
                connection.initiator_ephemeral_secret_fact_id,
            ))
            .offer(ephemeral_secret_closed_offer(
                fact.id,
                connection.responder_ephemeral_secret_fact_id,
            )))
    }
}

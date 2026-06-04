//! Connection ephemeral-secret projector.
//!
//! Ephemeral secrets are local handshake capabilities. Projection turns live
//! local secret facts into durable local rows plus exact context offers that
//! request/connection projectors can match by secret fact id. When a connection
//! close fact names the secret, the same owner deletes its row and purges its
//! own fact bytes.
//!
//! POLICY. A connection_ephemeral_secret is admitted iff:
//!   1. STRUCTURAL. The local-only body decodes and the stored public key
//!      re-derives from the private key.
//!   2. CONTEXT. If exact close context is present, it must be a local
//!      connection_close fact.
//!   3. MATERIALIZE. Live secrets publish a local ephemeral-secret offer and
//!      write the row keyed by this fact id. Closed secrets delete the row and
//!      purge their own fact bytes.
//!
//! Change this file when the local capability proof or materialized row changes.
//! Request and connection projectors own the context checks that consume this
//! offer.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{RowMutation, TableDelete};
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use super::rows::{
    connection_ephemeral_secret_key, connection_ephemeral_secret_row,
    CONNECTION_EPHEMERAL_SECRET_ROWS,
};
use crate::protocol::connection::close;

#[derive(Debug, Clone, Default)]
pub struct ConnectionEphemeralSecretProjector;

impl ConnectionEphemeralSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionEphemeralSecretProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::ConnectionEphemeralSecretAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionEphemeralSecretAuthenticator>
    for ConnectionEphemeralSecretProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::ConnectionEphemeralSecretFact>,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes and that
        // the public key re-derives from the private key. Scope is interpretation.
        let (fact, secret) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection ephemeral secret fact must have local scope".to_string());
        }

        // 2. Close gate.
        let close_need = close::ephemeral_secret_closed_need(fact.id, fact.id);
        if let Some(close_fact) = _context.payload_for(&close_need) {
            if close_fact.scope != FactScope::Local {
                return Err("connection ephemeral close context must be local".to_string());
            }
            let close = close::decode_fact_payload(close_fact.body()).map_err(|_| {
                "connection ephemeral close context is not a connection close".to_string()
            })?;
            if close.connection_id == [0; 32] {
                return Err("connection ephemeral close context has empty connection".to_string());
            }
            return Ok(ProjectionOutput::new()
                .row_mutation(RowMutation::DeleteRow(TableDelete {
                    table: CONNECTION_EPHEMERAL_SECRET_ROWS,
                    key: connection_ephemeral_secret_key(&fact.id),
                }))
                .purge_self(fact.id));
        }

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(close_need)
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_ephemeral_secret",
                crate::core::facts::FactScope::Local,
                fact.id,
                fact.id,
            ))
            .row_mutation(RowMutation::PutRow(connection_ephemeral_secret_row(
                fact.id, &secret,
            )?)))
    }
}

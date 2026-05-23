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

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::connection::response;

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
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ConnectionCloseProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        close: super::fact::ConnectionCloseFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection close fact must have local scope".to_string());
        }
        if close.connection_id == [0; 32] {
            return Err("connection close connection_id cannot be empty".to_string());
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
            .offer(super::connection_closed_offer(fact.id, close.connection_id))
            .offer(super::ephemeral_secret_closed_offer(
                fact.id,
                connection.initiator_ephemeral_secret_fact_id,
            ))
            .offer(super::ephemeral_secret_closed_offer(
                fact.id,
                connection.responder_ephemeral_secret_fact_id,
            )))
    }
}

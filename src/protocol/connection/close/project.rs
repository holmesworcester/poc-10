//! Connection-close projector.
//!
//! Close projection validates that a local close fact names a materialized
//! established connection. It then publishes close context keyed by the
//! connection id and by both ephemeral-secret fact ids carried by that state.
//!
//! POLICY. A connection_close is admitted iff:
//!   1. STRUCTURAL. The fact is local and names a non-empty connection id.
//!   2. CONTEXT. The exact local connection context for that id is present.
//!   3. MATERIALIZE. Publish close offers only; target facts own their own row
//!      deletion and self-purge when those offers wake them.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

use crate::protocol::connection::connection;

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

/// Staged read pipeline for the close fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "connection::close::Codec",
    authenticate: "connection::close::authenticate::ConnectionCloseAuthenticator",
    adapt: "connection::close::adapt::ConnectionCloseAdapter",
    project: "connection::close::project::ConnectionCloseProjector",
};

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
        project_staged::<
            super::Codec,
            super::authenticate::ConnectionCloseAuthenticator,
            super::adapt::ConnectionCloseAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::ConnectionCloseFact> for ConnectionCloseProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        close: super::fact::ConnectionCloseFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes and the
        // non-empty connection id. Scope is interpretation.
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection close fact must have local scope".to_string());
        }

        // 2. Context.
        let connection_need = connection::project::connection_need(fact.id, close.connection_id);
        let Some(connection_fact) = context.payload_for(&connection_need) else {
            return Ok(ProjectionOutput::new().need(connection_need));
        };
        if connection_fact.scope != FactScope::Local {
            return Err("connection close context must be local".to_string());
        }
        // 3. Materialize close context for the target owners.
        Ok(ProjectionOutput::new()
            .need(connection_need)
            .offer(connection_closed_offer(fact.id, close.connection_id)))
    }
}

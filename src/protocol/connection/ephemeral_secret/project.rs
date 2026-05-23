//! Connection ephemeral-secret projector.
//!
//! Ephemeral secrets are local handshake capabilities. Projection turns a
//! decoded local secret fact into a durable local row plus an exact context
//! offer that request/response projectors can match by secret fact id. No
//! remote or authority context is consulted because possession of the local
//! private key is the capability being recorded.
//!
//! POLICY. A connection_ephemeral_secret is admitted iff:
//!   1. STRUCTURAL. The local-only body decodes and the stored public key
//!      re-derives from the private key.
//!   2. CONTEXT. No remote or authority context is accepted; this is local key
//!      material only.
//!   3. MATERIALIZE. Publish a local ephemeral-secret offer and write the local
//!      secret row keyed by this fact id.
//!
//! Change this file when the local capability proof or materialized row changes.
//! Request and response projectors own the context checks that consume this
//! offer.

use crate::core::crypto;
use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use super::rows::connection_ephemeral_secret_row;

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
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ConnectionEphemeralSecretProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        secret: super::fact::ConnectionEphemeralSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if crypto::x25519_public_key(&secret.ephemeral_private_key) != secret.ephemeral_public_key {
            return Err("connection ephemeral public key does not match private key".to_string());
        }

        // 3. Materialize.
        Ok(ProjectionOutput::new()
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

//! Poc-10 connection ephemeral-secret projector.
//!
//! POLICY. A connection_ephemeral_secret is admitted iff:
//!   1. STRUCTURAL. The local-only body decodes and the stored public key
//!      re-derives from the private key.
//!   2. CONTEXT. No remote or authority context is accepted; this is local key
//!      material only.
//!   3. MATERIALIZE. Publish a local ephemeral-secret offer and write the local
//!      secret row keyed by this fact id.

use crate::core::crypto;
use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::matchers;

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
            .offer(matchers::connection_ephemeral_secret_offer(
                fact.id, fact.id,
            ))
            .intent(
                AtomicIntent::PutRow(connection_ephemeral_secret_row(fact.id, &secret)?)
                    .into_intent(),
            ))
    }
}

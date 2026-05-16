//! Poc-10 connection ephemeral-secret projector.
//!
//! Decodes the canonical body, checks the recorded public key matches the
//! recorded private key (the legacy invariant), and emits a single `PutRow`
//! keyed by the secret fact id.
//!
//! This fact is local-only (`FactScope::Local`): the ephemeral private key
//! never leaves the originating node.

use crate::core::crypto;
use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::matchers;
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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let secret = layout::decode_fact(&fact.bytes)?;
        if crypto::x25519_public_key(&secret.ephemeral_private_key) != secret.ephemeral_public_key {
            return Err("connection ephemeral public key does not match private key".to_string());
        }
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

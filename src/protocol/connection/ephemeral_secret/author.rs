//! Connection ephemeral-secret fact construction helpers.

use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::ConnectionEphemeralSecretFact;

pub fn random_secret_fact(
    owner_endpoint: FactId,
    created_at_ms: u64,
) -> Result<(ConnectionEphemeralSecretFact, Fact), String> {
    let ephemeral_private_key = crypto::random_x25519_private_key();
    let ephemeral = ConnectionEphemeralSecretFact {
        owner_endpoint,
        ephemeral_private_key,
        ephemeral_public_key: crypto::x25519_public_key(&ephemeral_private_key),
        created_at_ms,
    };
    fact_from_secret(ephemeral).map(|fact| (ephemeral, fact))
}

pub fn fact_from_secret(secret: ConnectionEphemeralSecretFact) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Local,
        secret.created_at_ms,
        encode::encode_fact(&secret)?,
    ))
}

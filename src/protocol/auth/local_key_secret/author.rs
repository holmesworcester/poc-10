//! Local key-secret fact construction helpers.

use crate::core::crypto::{self, XChaCha20Poly1305Key};
use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::LocalKeySecretFact;

pub fn random_secret_fact(
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    created_at_ms: u64,
) -> Result<(LocalKeySecretFact, Fact), String> {
    secret_fact(
        workspace_id,
        frontier_id,
        owner_endpoint_id,
        created_at_ms,
        crypto::random_xchacha20poly1305_key(),
    )
}

pub fn secret_fact(
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    created_at_ms: u64,
    key_secret: XChaCha20Poly1305Key,
) -> Result<(LocalKeySecretFact, Fact), String> {
    let secret = LocalKeySecretFact {
        workspace_id,
        frontier_id,
        owner_endpoint_id,
        created_at_ms,
        key_secret,
    };
    let fact = Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_local_key_secret(&secret)?,
    );
    Ok((secret, fact))
}

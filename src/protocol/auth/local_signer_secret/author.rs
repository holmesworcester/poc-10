//! Local signer-secret fact construction helpers.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::LocalSignerSecretFact;

pub fn signer_secret_fact(
    workspace_id: FactId,
    signer_id: FactId,
    public_key: Ed25519PublicKey,
    private_key: Ed25519PrivateKey,
    created_at_ms: u64,
) -> Result<(LocalSignerSecretFact, Fact), String> {
    let secret = LocalSignerSecretFact {
        workspace_id,
        signer_id,
        public_key,
        private_key,
    };
    let fact = Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_fact(&secret)?,
    );
    Ok((secret, fact))
}

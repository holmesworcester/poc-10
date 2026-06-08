//! Signature evidence authoring helpers.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId};

use super::fact::SignatureFact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredFactEvidence {
    pub fact: Fact,
    pub signature: Fact,
}

impl AuthoredFactEvidence {
    pub fn new(
        fact: Fact,
        workspace_id: FactId,
        signer_private_key: &Ed25519PrivateKey,
        created_at_ms: u64,
    ) -> Result<Self, String> {
        let signature = sign_fact(workspace_id, &fact, signer_private_key, created_at_ms)?;
        Ok(Self { fact, signature })
    }

    pub fn into_facts(self) -> [Fact; 2] {
        [self.fact, self.signature]
    }
}

pub fn sign_fact(
    workspace_id: FactId,
    target: &Fact,
    signer_private_key: &Ed25519PrivateKey,
    created_at_ms: u64,
) -> Result<Fact, String> {
    create_signature(workspace_id, target.id, signer_private_key, created_at_ms)
}

pub fn sign_facts(
    workspace_id: FactId,
    targets: &[Fact],
    signer_private_key: &Ed25519PrivateKey,
    created_at_ms: u64,
) -> Result<Vec<Fact>, String> {
    targets
        .iter()
        .map(|target| sign_fact(workspace_id, target, signer_private_key, created_at_ms))
        .collect()
}

pub fn create_signature(
    workspace_id: FactId,
    target_fact_id: FactId,
    signer_private_key: &Ed25519PrivateKey,
    created_at_ms: u64,
) -> Result<Fact, String> {
    let fact = SignatureFact {
        workspace_id,
        created_at_ms,
        target_fact_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        signature: crypto::ed25519_sign(
            signer_private_key,
            &super::encode::signature_message(workspace_id, target_fact_id),
        ),
    };
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        super::encode::encode_fact(&fact)?,
    ))
}

//! Signature evidence authoring helpers.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId};

use super::fact::SignatureFact;

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

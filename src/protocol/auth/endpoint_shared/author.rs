//! Deterministic constructors for endpoint-shared facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::endpoint_shared::encode;
use crate::protocol::auth::endpoint_shared::fact::{
    EndpointDeviceName, EndpointId, EndpointRole, EndpointSharedFact,
};

#[allow(clippy::too_many_arguments)]
pub fn signed_endpoint_shared_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_authority_fact_id: FactId,
    endpoint_id: EndpointId,
    signing_public_key: Ed25519PublicKey,
    endpoint_role: EndpointRole,
    device_name: &str,
    signer_id: FactId,
    signer_private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    let mut payload = EndpointSharedFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id,
        endpoint_id,
        signing_public_key,
        endpoint_role,
        device_name: EndpointDeviceName::new(device_name)
            .map_err(|err| format!("endpoint device name: {err}"))?,
        signer_id,
        signer_public_key: crypto::ed25519_public_key(&signer_private_key),
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let (_, signature) = crypto::ed25519_sign_canonical(
        &signer_private_key,
        &crate::protocol::canonical::encode_with_zeroed_trailing_signature(
            &payload,
            encode::encode_fact,
        )?,
    );
    payload.signature = signature;
    let bytes = encode::encode_fact(&payload)?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

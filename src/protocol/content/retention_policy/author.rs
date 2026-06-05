//! Deterministic constructor for retention policy facts.
//!
//! This layer takes already-resolved parameters and the signer private key and
//! returns the canonical, signed fact bytes. API and CLI workflows that need
//! command context, local capabilities, or multi-fact orchestration belong in
//! `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::content::retention_policy::encode;
use crate::protocol::content::retention_policy::fact::RetentionPolicyFact;

#[allow(clippy::too_many_arguments)]
pub fn signed_retention_policy_fact(
    workspace_id: FactId,
    supersedes_policy_id: Option<FactId>,
    ttl_minutes: u32,
    retire_minute: u64,
    scope_kind: u8,
    scope_id: FactId,
    author_user_id: FactId,
    signer_id: FactId,
    created_at_ms: u64,
    signer_private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    let signer_public_key = crypto::ed25519_public_key(&signer_private_key);
    let mut payload = RetentionPolicyFact {
        workspace_id,
        supersedes_policy_id,
        ttl_minutes,
        retire_minute,
        scope_kind,
        scope_id,
        author_user_id,
        signer_id,
        signer_public_key,
        created_at_ms,
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
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        encode::encode_fact(&payload)?,
    ))
}

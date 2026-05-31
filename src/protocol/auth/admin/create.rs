//! Deterministic constructors for admin grant facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::admin::fact::AdminFact;
use crate::protocol::auth::admin::layout;

pub fn signed_admin_fact(
    created_at_ms: u64,
    signer_id: FactId,
    signer_private_key: Ed25519PrivateKey,
    mut grant: AdminFact,
) -> Result<Fact, String> {
    grant.signer_id = signer_id;
    grant.signer_public_key = crypto::ed25519_public_key(&signer_private_key);
    grant.signature = [0; crypto::ED25519_SIGNATURE_BYTES];
    let (_, signature) =
        crypto::ed25519_sign_canonical(&signer_private_key, &layout::signing_bytes(&grant)?);
    grant.signature = signature;
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        layout::encode_fact(&grant)?,
    ))
}

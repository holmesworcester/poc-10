//! Deterministic constructors for user-invite facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need store-queried local capabilities,
//! or multi-fact orchestration belong in `api.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::user_invite::encode;
use crate::protocol::auth::user_invite::fact::UserInviteFact;

#[allow(clippy::too_many_arguments)]
pub fn authored_user_invite_fact(
    created_at_ms: u64,
    public_key: Ed25519PublicKey,
    workspace_id: FactId,
    authority_fact_id: FactId,
    signer_id: FactId,
    signer_private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    if workspace_id == [0; 32] {
        return Err("user_invite workspace_id cannot be empty".to_string());
    }
    if authority_fact_id == [0; 32] {
        return Err("user_invite authority_fact_id cannot be empty".to_string());
    }
    if public_key == [0; 32] {
        return Err("user_invite public_key cannot be empty".to_string());
    }
    let signer_public_key = crypto::ed25519_public_key(&signer_private_key);
    let payload = UserInviteFact {
        created_at_ms,
        public_key,
        workspace_id,
        authority_fact_id,
        signer_id,
        signer_public_key,
    };
    let bytes = encode::encode_fact(&payload)?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

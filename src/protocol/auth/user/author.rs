//! Deterministic constructors for user facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};

use super::encode;
use super::fact::{UserFact, Username};

#[allow(clippy::too_many_arguments)]
pub fn authored_user_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    public_key: Ed25519PublicKey,
    username: &str,
    signer_id: FactId,
    signer_private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    if workspace_id == [0; 32] {
        return Err("user workspace_id cannot be empty".to_string());
    }
    if signer_id == [0; 32] {
        return Err("user signer_id cannot be empty".to_string());
    }
    if public_key == [0; 32] {
        return Err("user public_key cannot be empty".to_string());
    }
    if username.trim().is_empty() {
        return Err("username must not be empty".to_string());
    }
    let signer_public_key = crypto::ed25519_public_key(&signer_private_key);
    let payload = UserFact {
        created_at_ms,
        workspace_id,
        public_key,
        username: Username::new(username).map_err(|err| format!("username: {err}"))?,
        signer_id,
        signer_public_key,
    };
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        encode::encode_fact(&payload)?,
    ))
}

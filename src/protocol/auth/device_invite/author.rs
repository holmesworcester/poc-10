//! Deterministic constructors for device-invite facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::device_invite::encode;
use crate::protocol::auth::device_invite::fact::DeviceInviteFact;

#[allow(clippy::too_many_arguments)]
pub fn signed_device_invite_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_authority_fact_id: FactId,
    user_invite_fact_id: Option<FactId>,
    public_key: crypto::Ed25519PublicKey,
    signer_id: FactId,
    signer_private_key: [u8; 32],
) -> Result<Fact, String> {
    let payload = DeviceInviteFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id,
        user_invite_fact_id,
        public_key,
        signer_id,
        signer_public_key: crypto::ed25519_public_key(&signer_private_key),
    };
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        encode::encode_fact(&payload)?,
    ))
}

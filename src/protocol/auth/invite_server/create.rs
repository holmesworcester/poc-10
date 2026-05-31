//! Deterministic constructors for invite-server facts.
//!
//! This layer takes already-resolved parameters and the signer private key,
//! builds the canonical fact, signs it, and returns the encoded fact. API and
//! CLI workflows that need command context, local capabilities, or multi-fact
//! orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::invite_server::fact::{InviteServerFact, WorkspaceId};
use crate::protocol::auth::invite_server::layout;

#[allow(clippy::too_many_arguments)]
pub fn signed_invite_server_fact(
    created_at_ms: u64,
    public_key: Ed25519PublicKey,
    workspace_id: WorkspaceId,
    authority_fact_id: FactId,
    signer_id: FactId,
    signer_public_key: Ed25519PublicKey,
    signer_private_key: &Ed25519PrivateKey,
) -> Result<Fact, String> {
    let invite_server = InviteServerFact {
        created_at_ms,
        public_key,
        workspace_id,
        authority_fact_id,
        signer_id,
        signer_public_key,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let mut invite_server = invite_server;
    let (_, signature) =
        crypto::ed25519_sign_canonical(signer_private_key, &layout::signing_bytes(&invite_server)?);
    invite_server.signature = signature;
    let bytes = layout::encode_fact(&invite_server)?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

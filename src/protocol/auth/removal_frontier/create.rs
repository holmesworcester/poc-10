//! Deterministic constructors for removal frontier facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::Fact;
use crate::protocol::auth::removal_frontier::fact::{EndpointId, RemovalFrontierFact, WorkspaceId};
use crate::protocol::auth::removal_frontier::layout;

pub fn signed_removal_frontier_fact(
    workspace_id: WorkspaceId,
    owner_endpoint_id: EndpointId,
    created_at_ms: u64,
    private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    let signer_public_key = crypto::ed25519_public_key(&private_key);
    let mut frontier = RemovalFrontierFact {
        workspace_id,
        owner_endpoint_id,
        created_at_ms,
        signer_public_key,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let (_, signature) =
        crypto::ed25519_sign_canonical(&private_key, &layout::signing_bytes(&frontier)?);
    frontier.signature = signature;
    let bytes = layout::encode_removal_frontier(&frontier)?;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        bytes,
    ))
}

//! Deterministic constructors for removal frontier facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::Fact;
use crate::protocol::auth::removal_frontier::encode;
use crate::protocol::auth::removal_frontier::fact::{EndpointId, RemovalFrontierFact, WorkspaceId};

pub fn signed_removal_frontier_fact(
    workspace_id: WorkspaceId,
    owner_endpoint_id: EndpointId,
    created_at_ms: u64,
    private_key: Ed25519PrivateKey,
) -> Result<Fact, String> {
    let signer_public_key = crypto::ed25519_public_key(&private_key);
    let frontier = RemovalFrontierFact {
        workspace_id,
        owner_endpoint_id,
        created_at_ms,
        signer_public_key,
    };
    let bytes = encode::encode_removal_frontier(&frontier)?;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        bytes,
    ))
}

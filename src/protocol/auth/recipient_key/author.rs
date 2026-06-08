//! Deterministic constructors for recipient key facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::{Fact, FactId};
use crate::protocol::auth::recipient_key::encode;
use crate::protocol::auth::recipient_key::fact::{EndpointId, RecipientKeyFact, WorkspaceId};

pub fn signed_recipient_key_fact(
    workspace_id: WorkspaceId,
    endpoint_id: EndpointId,
    recipient_key: FactId,
    previous_recipient_key_id: FactId,
    created_at_ms: u64,
    signer_public_key: Ed25519PublicKey,
) -> Result<Fact, String> {
    let recipient = RecipientKeyFact {
        workspace_id,
        endpoint_id,
        recipient_key,
        previous_recipient_key_id,
        created_at_ms,
        signer_public_key,
    };
    let bytes = encode::encode_recipient_key(&recipient)?;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        bytes,
    ))
}

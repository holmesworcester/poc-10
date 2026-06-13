//! Deterministic constructors for invite-server facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need store-queried local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::invite_server::encode;
use crate::protocol::auth::invite_server::fact::{InviteServerFact, WorkspaceId};

#[allow(clippy::too_many_arguments)]
pub fn authored_invite_server_fact(
    created_at_ms: u64,
    public_key: Ed25519PublicKey,
    workspace_id: WorkspaceId,
    authority_fact_id: FactId,
    signer_id: FactId,
    signer_public_key: Ed25519PublicKey,
) -> Result<Fact, String> {
    let invite_server = InviteServerFact {
        created_at_ms,
        public_key,
        workspace_id,
        authority_fact_id,
        signer_id,
        signer_public_key,
    };
    let bytes = encode::encode_fact(&invite_server)?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

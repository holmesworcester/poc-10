//! Deterministic constructors for workspace facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactScope};
use crate::protocol::auth::workspace::fact::{WorkspaceFact, WorkspaceName, WORKSPACE_NAME_BYTES};
use crate::protocol::auth::workspace::layout;

pub fn create_workspace(
    created_at_ms: u64,
    private_key: Ed25519PrivateKey,
    name: &str,
) -> Result<Fact, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("create_workspace name must not be blank".to_string());
    }
    if name.len() > WORKSPACE_NAME_BYTES {
        return Err(format!(
            "create_workspace name exceeds {WORKSPACE_NAME_BYTES} byte slot"
        ));
    }

    let public_key = crypto::ed25519_public_key(&private_key);
    let workspace = WorkspaceFact {
        created_at_ms,
        public_key,
        name: WorkspaceName::new(name).map_err(|err| format!("workspace name: {err}"))?,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let mut workspace = workspace;
    let (_, signature) =
        crypto::ed25519_sign_canonical(&private_key, &layout::signing_bytes(&workspace)?);
    workspace.signature = signature;
    let bytes = layout::encode_fact(&workspace)?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

//! Pure workspace fact authoring.
//!
//! This layer takes explicit inputs and signing material, builds the typed
//! source value, signs canonical bytes, encodes bytes, and returns the
//! fact. Runtime gathering and command orchestration belong in `commands.rs`.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::core::facts::{Fact, FactScope};

use super::fact::{WorkspaceFact, WorkspaceName, WORKSPACE_NAME_BYTES};

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
    let (_, signature) = crypto::ed25519_sign_canonical(
        &private_key,
        &crate::protocol::canonical::encode_with_zeroed_trailing_signature(
            &workspace,
            super::encode::encode_fact,
        )?,
    );
    workspace.signature = signature;
    let bytes = super::encode::encode_fact(&workspace)?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

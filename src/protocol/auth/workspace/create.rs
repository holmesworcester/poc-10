//! Deterministic constructors for workspace facts.
//!
//! This layer takes already-resolved parameters and returns the canonical fact
//! bytes. API and CLI workflows that need command context, local capabilities,
//! or multi-fact orchestration belong in `commands.rs`.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::{Fact, FactScope};
use crate::protocol::auth::workspace::fact::{WorkspaceFact, WORKSPACE_NAME_BYTES};
use crate::protocol::auth::workspace::layout;

pub fn create_workspace(
    created_at_ms: u64,
    public_key: Ed25519PublicKey,
    name: &str,
) -> Result<Fact, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("create_workspace name must not be blank".to_string());
    }
    if name.as_bytes().len() > WORKSPACE_NAME_BYTES {
        return Err(format!(
            "create_workspace name exceeds {WORKSPACE_NAME_BYTES} byte slot"
        ));
    }

    let workspace = WorkspaceFact {
        created_at_ms,
        public_key,
        name: name.to_string(),
    };
    let bytes = layout::encode_fact(&workspace)?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

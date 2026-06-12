//! Local signer-secret semantic adapter.
//!
//! The current local_signer_secret wire shape is already the active semantic
//! shape. This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::LocalSignerSecretFact;

pub(crate) fn adapt(source: LocalSignerSecretFact) -> Result<LocalSignerSecretFact, String> {
    Ok(source)
}

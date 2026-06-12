//! Local key secret semantic adapter.
//!
//! The current local_key_secret wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::LocalKeySecretFact;

pub(crate) fn adapt(source: LocalKeySecretFact) -> Result<LocalKeySecretFact, String> {
    Ok(source)
}

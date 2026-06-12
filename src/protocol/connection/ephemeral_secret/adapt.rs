//! Connection ephemeral-secret semantic adapter.
//!
//! The current ephemeral_secret wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::ConnectionEphemeralSecretFact;

pub(crate) fn adapt(
    source: ConnectionEphemeralSecretFact,
) -> Result<ConnectionEphemeralSecretFact, String> {
    Ok(source)
}

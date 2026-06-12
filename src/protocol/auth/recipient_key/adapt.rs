//! Recipient key semantic adapter.
//!
//! The current recipient_key wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::RecipientKeyFact;

pub(crate) fn adapt(source: RecipientKeyFact) -> Result<RecipientKeyFact, String> {
    Ok(source)
}

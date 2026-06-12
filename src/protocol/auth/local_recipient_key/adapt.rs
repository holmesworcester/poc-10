//! Local recipient key semantic adapter.
//!
//! The current local_recipient_key wire shape is already the active semantic
//! shape. This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::LocalRecipientKeyFact;

pub(crate) fn adapt(source: LocalRecipientKeyFact) -> Result<LocalRecipientKeyFact, String> {
    Ok(source)
}

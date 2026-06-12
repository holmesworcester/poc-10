//! Content-message-deletion semantic adapter.
//!
//! The current message_deletion wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::ContentMessageDeletionFact;

pub(crate) fn adapt(
    source: ContentMessageDeletionFact,
) -> Result<ContentMessageDeletionFact, String> {
    Ok(source)
}

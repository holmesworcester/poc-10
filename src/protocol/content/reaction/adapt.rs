//! Content-reaction semantic adapter.
//!
//! The current reaction wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::ContentReactionFact;

pub(crate) fn adapt(source: ContentReactionFact) -> Result<ContentReactionFact, String> {
    Ok(source)
}

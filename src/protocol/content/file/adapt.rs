//! Content-file semantic adapter.
//!
//! The current file wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::ContentFileFact;

pub(crate) fn adapt(source: ContentFileFact) -> Result<ContentFileFact, String> {
    Ok(source)
}

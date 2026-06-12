//! Content-file-deletion semantic adapter.
//!
//! The current file_deletion wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::ContentFileDeletionFact;

pub(crate) fn adapt(source: ContentFileDeletionFact) -> Result<ContentFileDeletionFact, String> {
    Ok(source)
}

//! Content-file-slice semantic adapter.
//!
//! The current file_slice wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::ContentFileSliceFact;

pub(crate) fn adapt(source: ContentFileSliceFact) -> Result<ContentFileSliceFact, String> {
    Ok(source)
}

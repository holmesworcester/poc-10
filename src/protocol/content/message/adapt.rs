//! Content-message semantic adapter.
//!
//! The current content-message wire shape is already the active semantic
//! shape. This identity adapter keeps the staged route explicit and gives
//! future versioned facts a dedicated conversion point.

use super::fact::ContentMessageFact;

pub(crate) fn adapt(source: ContentMessageFact) -> Result<ContentMessageFact, String> {
    Ok(source)
}

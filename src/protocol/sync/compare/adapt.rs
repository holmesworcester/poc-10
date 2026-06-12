//! Sync compare semantic adapter.
//!
//! The current compare wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::SyncCompareFact;

pub(crate) fn adapt(source: SyncCompareFact) -> Result<SyncCompareFact, String> {
    Ok(source)
}

//! Sync range-request semantic adapter.
//!
//! The current range_request wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::SyncRangeRequestFact;

pub(crate) fn adapt(source: SyncRangeRequestFact) -> Result<SyncRangeRequestFact, String> {
    Ok(source)
}
